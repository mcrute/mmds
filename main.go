package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/sid77/drop"
	jww "github.com/spf13/jwalterweatherman"
)

var (
	DEFAULT_VALUES map[string]*string
)

const (
	METADATA_FILE = "/etc/mmds/bootstrap-cred.json"
)

type FileLike interface {
	io.Reader
	io.Writer
	io.Seeker
	Truncate(int64) error
}

func init() {
	DEFAULT_VALUES = map[string]*string{
		"domain":            StringPtr("amazonaws.com"),
		"partition":         StringPtr("aws"),
		"ami-launch-index":  StringPtr("0"),
		"ami-manifest-path": StringPtr("(unknown)"),
		"instance-action":   StringPtr("none"),
		"profile":           StringPtr("default-hvm"),
		"security-groups":   StringPtr("default"),
	}
}

func StringPtr(v string) *string {
	return &v
}

type appContext struct {
	PrivateIP         *net.IP
	Region            *string
	MacAddr           *net.HardwareAddr
	AvailabilityZone  *string
	Hostname          *string
	InstanceId        *string
	InstanceType      *string
	AccountId         *int64
	ImageId           *string
	ReservationId     *string
	InstanceProfileId *string
	RoleARN           *string
	BootstrapSecret   *string
	CredentialHandler CredentialHandler
	CredentialFile    FileLike
}

func (c *appContext) FormatAZ() string {
	return fmt.Sprintf("%s%s", *c.Region, *c.AvailabilityZone)
}

func GetKeyHandler(content map[string]*string, key string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(*content[key]))
	})
}

func AvailabilityZoneHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)
	fmt.Fprintf(w, ctx.FormatAZ())
}

func IAMCredentialHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)
	vars := mux.Vars(r)

	name, err := parseRoleName(*ctx.RoleARN)
	if err != nil {
		jww.ERROR.Printf("Error parsing role name in IAMCredentialHandler: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	if vars["profile"] != name {
		http.NotFound(w, r)
		return
	}

	writeHTTPJson(w, <-ctx.CredentialHandler.Output(), "IAMCredentialHandler")
}

func StatusHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)
	writeHTTPJson(w, ctx.CredentialHandler.InGoodState(), "IAMCredentialHandler")
}

type bootstrapInput struct {
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Signature       string
}

func validateSignature(r *bootstrapInput, key *string) bool {
	buf := bytes.Buffer{}
	// Alphabetical order matters here
	buf.WriteString(fmt.Sprintf("AccessKeyId%s", r.AccessKeyId))
	buf.WriteString(fmt.Sprintf("SecretAccessKey%s", r.SecretAccessKey))

	// Only hash token if it was presented
	if r.Token != "" {
		buf.WriteString(fmt.Sprintf("Token%s", r.Token))
	}

	mac := hmac.New(sha256.New, []byte(*key))
	mac.Write(buf.Bytes())
	expected := mac.Sum(nil)

	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return false
	}

	return hmac.Equal(expected, sig)
}

func BootstrapCredentialHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)
	d := json.NewDecoder(r.Body)
	var cred bootstrapInput

	err := d.Decode(&cred)
	if err != nil {
		jww.ERROR.Printf("Error decoding bootstrap JSON: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if !validateSignature(&cred, ctx.BootstrapSecret) {
		jww.ERROR.Printf("Invalid signature for bootstrapping credentials")
		http.Error(w, "Not allowed", http.StatusForbidden)
		return
	}

	creds := credentials.NewStaticCredentials(cred.AccessKeyId, cred.SecretAccessKey, cred.Token)
	ctx.CredentialHandler.SetBootstrapCredential(creds)

	jd, err := json.MarshalIndent(cred, "", " ")
	if err != nil {
		jww.ERROR.Printf("Unable to marshal credential for writing to file")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Truncate credential file and update with new credentials
	// TODO: Should validate the the credentials worked first
	ctx.CredentialFile.Seek(0, 0)
	ctx.CredentialFile.Truncate(0)
	ctx.CredentialFile.Write(jd)
}

func IAMInfoHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)

	p := &ec2metadata.EC2IAMInfo{
		Code:               "Success",
		LastUpdated:        time.Now().UTC().Round(time.Second),
		InstanceProfileArn: *ctx.RoleARN,
		InstanceProfileID:  *ctx.InstanceProfileId,
	}

	writeHTTPJson(w, p, "IAMInfoHandler")
}

func InstanceProfileListHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)

	if !ctx.CredentialHandler.InGoodState() {
		jww.ERROR.Printf("Credential handler in a bad state")
		fmt.Fprintf(w, "")
		return
	}

	name, err := parseRoleName(*ctx.RoleARN)
	if err != nil {
		jww.ERROR.Printf("Error parsing role name in InstanceProfileListHandler: %s", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}

	fmt.Fprintf(w, name)
}

func IdentityDocumentHandler(w http.ResponseWriter, r *http.Request) {
	ctx := getAppCtx(r)

	id := &ec2metadata.EC2InstanceIdentityDocument{
		PrivateIP:          ctx.PrivateIP.String(),
		DevpayProductCodes: nil,
		AvailabilityZone:   ctx.FormatAZ(),
		Version:            "2010-08-31",
		InstanceID:         *ctx.InstanceId,
		BillingProducts:    nil,
		InstanceType:       *ctx.InstanceType,
		ImageID:            *ctx.ImageId,
		AccountID:          strconv.FormatInt(*ctx.AccountId, 10),
		Architecture:       "x86_64",
		KernelID:           "",
		RamdiskID:          "",
		PendingTime:        time.Now().Round(time.Second),
		Region:             *ctx.Region,
	}

	writeHTTPJson(w, id, "IdentityDocumentHandler")
}

func buildMetadataHandler(ctx *appContext, defaults map[string]*string) http.Handler {
	r := mux.NewRouter()

	// Static Data Handlers
	r.Handle("/latest/meta-data/services/domain", GetKeyHandler(defaults, "domain"))
	r.Handle("/latest/meta-data/services/partition", GetKeyHandler(defaults, "partition"))
	r.Handle("/latest/meta-data/ami-launch-index", GetKeyHandler(defaults, "ami-launch-index"))
	r.Handle("/latest/meta-data/ami-manifest-path", GetKeyHandler(defaults, "ami-manifest-path"))
	r.Handle("/latest/meta-data/instance-action", GetKeyHandler(defaults, "instance-action"))
	r.Handle("/latest/meta-data/profile", GetKeyHandler(defaults, "profile"))
	r.Handle("/latest/meta-data/security-groups", GetKeyHandler(defaults, "security-groups"))

	// Machine-specific Pseudo-static Handlers
	r.Handle("/latest/meta-data/mac", ContextPrintingHandler{ctx, "MacAddr"})
	r.Handle("/latest/meta-data/hostname", ContextPrintingHandler{ctx, "Hostname"})
	r.Handle("/latest/meta-data/local-hostname", ContextPrintingHandler{ctx, "Hostname"})
	r.Handle("/latest/meta-data/local-ipv4", ContextPrintingHandler{ctx, "PrivateIP"})
	r.Handle("/latest/meta-data/instance-id", ContextPrintingHandler{ctx, "InstanceId"})
	r.Handle("/latest/meta-data/instance-type", ContextPrintingHandler{ctx, "InstanceType"})
	r.Handle("/latest/meta-data/ami-id", ContextPrintingHandler{ctx, "ImageId"})
	r.Handle("/latest/meta-data/reservation-id", ContextPrintingHandler{ctx, "ReservationId"})

	// Context-specific Handlers
	r.Handle("/latest/meta-data/placement/availability-zone", ContextAwareHandler{ctx, AvailabilityZoneHandler})
	r.Handle("/latest/dynamic/instance-identity/document", ContextAwareHandler{ctx, IdentityDocumentHandler})

	// IAM Credential Handlers
	r.Handle("/latest/meta-data/iam/info", ContextAwareHandler{ctx, IAMInfoHandler})
	r.Handle("/latest/meta-data/iam/security-credentials/", ContextAwareHandler{ctx, InstanceProfileListHandler})
	r.Handle("/latest/meta-data/iam/security-credentials/{profile}", ContextAwareHandler{ctx, IAMCredentialHandler})

	return handlers.LoggingHandler(os.Stdout, SecurityHandler{r})
}

func buildAdminHandler(ctx *appContext) http.Handler {
	r := mux.NewRouter()

	r.Handle("/bootstrap/creds", ContextAwareHandler{ctx, BootstrapCredentialHandler}).Methods("POST")
	r.Handle("/status", ContextAwareHandler{ctx, StatusHandler}).Methods("GET")

	return handlers.LoggingHandler(os.Stdout, r)
}

type UserArgs struct {
	regionAZ         string
	InstanceType     string
	Region           string
	AvailabilityZone string
	RoleARN          string
	User             string
	AccountNumber    int64
	BootstrapSecret  string
}

func parseArgs() (*UserArgs, error) {
	a := &UserArgs{}

	flag.StringVar(&a.regionAZ, "region", "us-west-2a", "region and availability zone")
	flag.StringVar(&a.InstanceType, "instance", "t2.micro", "instance type")
	flag.StringVar(&a.RoleARN, "arn", "", "ARN of role to assume")
	flag.StringVar(&a.User, "user", "nobody", "run-as user after port binding")
	flag.StringVar(&a.BootstrapSecret, "secret", "", "bootstrap signing secret")

	flag.Parse()

	_, err := user.Lookup(a.User)
	if err != nil {
		return nil, err
	}

	region, az, err := parseRegionAZ(a.regionAZ)
	if err != nil {
		return nil, err
	}
	a.Region = region
	a.AvailabilityZone = az

	act, err := parseAccountFromARN(a.RoleARN)
	if err != nil {
		return nil, err
	}
	a.AccountNumber = act

	if a.BootstrapSecret == "" {
		return nil, errors.New("Bootstrap secret must be set")
	}

	return a, nil
}

func initialBootstrap(file FileLike, handler CredentialHandler) {
	bd, err := ioutil.ReadAll(file)
	if err != nil {
		jww.ERROR.Printf("Error reading bootstrap file: %s", err.Error())
		return
	}

	var cred bootstrapInput
	err = json.Unmarshal(bd, &cred)
	if err != nil {
		jww.ERROR.Printf("Error decoding bootstrap JSON: %s", err)
		return
	}

	creds := credentials.NewStaticCredentials(cred.AccessKeyId, cred.SecretAccessKey, cred.Token)
	handler.SetBootstrapCredential(creds)
}

func main() {
	jww.SetStdoutThreshold(jww.LevelInfo)

	args, err := parseArgs()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	// Bind this port first because it requires privilges then drop the
	// privileges before we do anything else
	metalistener, err := net.Listen("tcp", "169.254.169.254:80")
	if err != nil {
		jww.FATAL.Printf("Error setting up listener: %s", err.Error())
		return
	}

	// Open this before dropping privileges because only root can update the
	// file but the service may need to update it at some future point if a new
	// credential is provided.
	credfile, err := os.OpenFile(METADATA_FILE, os.O_RDWR, 0600)
	if err != nil {
		jww.FATAL.Printf("Unable to open bootstrap credential file")
		return
	}
	defer credfile.Close()

	if err := drop.DropPrivileges(args.User); err != nil {
		jww.FATAL.Printf("Unable to drop privileges")
		return
	}

	iface, err := getInterfaceContext()
	if err != nil {
		jww.FATAL.Printf("Error getting network interface info: %s", err)
		return
	}

	credHandler := NewCredentialHandler(
		&args.Region,
		&args.RoleARN,
		iface.PrimaryHostname,
	)

	ctx := &appContext{
		PrivateIP:         iface.PrimaryIP,
		Region:            &args.Region,
		MacAddr:           iface.MacAddr,
		AvailabilityZone:  &args.AvailabilityZone,
		Hostname:          iface.PrimaryHostname,
		InstanceId:        generateInstanceId(iface.PrimaryHostname),
		InstanceType:      &args.InstanceType,
		AccountId:         &args.AccountNumber,
		ReservationId:     generatePlausibleId("r"),
		ImageId:           generatePlausibleId("ami"),
		InstanceProfileId: generatePlausibleProfileId(),
		RoleARN:           &args.RoleARN,
		BootstrapSecret:   &args.BootstrapSecret,
		CredentialHandler: credHandler,
		CredentialFile:    credfile,
	}

	initialBootstrap(credfile, credHandler)

	go credHandler.Start()
	go http.ListenAndServe(":8000", buildAdminHandler(ctx))
	ListenAndServeRaw(metalistener, buildMetadataHandler(ctx, DEFAULT_VALUES))
}
