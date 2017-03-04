package main

import (
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	jww "github.com/spf13/jwalterweatherman"
)

// Try to refresh credentials 3 times an hour but in the worst case if the
// credential refresh fails twice try to get one last refresh in before the end
// of the hour when the credential expires.
const REFRESH_INTERVAL = time.Duration(19) * time.Minute

type CredentialHandler interface {
	Start()
	InGoodState() bool
	SetBootstrapCredential(*credentials.Credentials)
	Output() chan *IAMCredentials
}

type credentialHandler struct {
	region         *string
	roleARN        *string
	sessionName    *string
	bootstrapCreds *credentials.Credentials
	output         chan *IAMCredentials
	input          chan *credentials.Credentials
}

func NewCredentialHandler(region, arn, name *string) CredentialHandler {
	return &credentialHandler{
		region:      region,
		roleARN:     arn,
		sessionName: name,
		output:      make(chan *IAMCredentials),
		input:       make(chan *credentials.Credentials, 1), // 1-item buffer to allow pre-start bootstrapping
	}
}

func (h *credentialHandler) Output() chan *IAMCredentials {
	return h.output
}

func (h *credentialHandler) InGoodState() bool {
	c := <-h.Output()
	return c.Code == "Success"
}

func (h *credentialHandler) SetBootstrapCredential(bc *credentials.Credentials) {
	h.input <- bc
}

func (h *credentialHandler) Start() {
	c := &IAMCredentials{Code: "Failure"}
	updateChan := make(chan *IAMCredentials)

	ticker := time.NewTicker(REFRESH_INTERVAL)
	defer ticker.Stop()

	jww.INFO.Printf("Starting credential handler, awaiting bootstrap")

	for {
		select {
		// Read and update bootstrap credentials
		case h.bootstrapCreds = <-h.input:
			go h.refreshCredential(nil, updateChan)
		// HTTP handler requests credential
		case h.output <- c:
		// Time to refresh credentials
		case <-ticker.C:
			go h.refreshCredential(c.rawCredentials, updateChan)
		// Updated credentials arrive
		case up := <-updateChan:
			if up == nil && c.Expiration.After(time.Now()) {
				c = &IAMCredentials{Code: "Failure"}
			} else {
				c = up
			}
		}
	}
}

func (h *credentialHandler) refreshCredential(creds *credentials.Credentials, out chan *IAMCredentials) {
	jww.INFO.Printf("Attempting to obtain credentials")

	if creds == nil && h.bootstrapCreds == nil {
		jww.WARN.Printf("No session or bootstrap credentials available")
		return
	}

	if creds != nil {
		jww.DEBUG.Printf("Attempting to use session credentials")

		c, err := h.assumeRole(creds)
		if err != nil {
			jww.WARN.Printf("Failed to obtain with session credentials: %s", err)
		} else {
			jww.INFO.Printf("Successfully obtained credentials")
			out <- c
			return
		}
	}

	if h.bootstrapCreds != nil {
		jww.DEBUG.Printf("Attempting to use bootstrap credentials")

		c, err := h.assumeRole(h.bootstrapCreds)
		if err != nil {
			jww.WARN.Printf("Failed to obtain with bootstrap credentials: %s", err)
		} else {
			jww.INFO.Printf("Successfully obtained credentials")
			out <- c
			return
		}
	}

	jww.ERROR.Printf("Failed to obtain credentials")
	out <- nil
}

func (h *credentialHandler) assumeRole(creds *credentials.Credentials) (*IAMCredentials, error) {
	ses := session.New(&aws.Config{
		Region:      h.region,
		Credentials: creds,
	})

	assumed, err := sts.New(ses).AssumeRole(&sts.AssumeRoleInput{
		RoleArn:         h.roleARN,
		RoleSessionName: h.sessionName,
	})
	if err != nil {
		return nil, err
	}

	return &IAMCredentials{
		Code:            "Success",
		Type:            "AWS-HMAC",
		AccessKeyId:     *assumed.Credentials.AccessKeyId,
		SecretAccessKey: *assumed.Credentials.SecretAccessKey,
		Token:           *assumed.Credentials.SessionToken,
		LastUpdated:     time.Now().UTC().Round(time.Second),
		Expiration:      *assumed.Credentials.Expiration,
		rawCredentials: credentials.NewStaticCredentials(
			*assumed.Credentials.AccessKeyId,
			*assumed.Credentials.SecretAccessKey,
			*assumed.Credentials.SessionToken,
		),
	}, nil
}
