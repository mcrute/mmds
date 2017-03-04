package main

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws/credentials"
)

var (
	REGION_AZ_REGEXP = regexp.MustCompile("((?:us|ca|eu|ap|sa)-(?:north|south)?(?:east|west)-\\d)([a-f])")
)

type IAMCredentials struct {
	Code            string
	LastUpdated     time.Time
	Type            string
	AccessKeyId     string
	SecretAccessKey string
	Token           string
	Expiration      time.Time
	rawCredentials  *credentials.Credentials
}

func generatePlausibleId(prefix string) *string {
	b := make([]byte, 10)
	rand.Read(b)
	h := sha1.New().Sum(b)
	o := fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(h)[0:17])
	return &o
}

func generateInstanceId(hostname *string) *string {
	h := sha1.New().Sum([]byte(*hostname))
	o := fmt.Sprintf("i-%s", hex.EncodeToString(h)[0:17])
	return &o
}

func generatePlausibleProfileId() *string {
	b := make([]byte, 16)
	rand.Read(b)

	for i, bb := range b {
		if bb%3 == 0 {
			b[i] = bb%10 + 48
		} else {
			b[i] = bb%26 + 65
		}
	}

	res := fmt.Sprintf("AIPAI%s", string(b))

	return &res
}

func parseAccountFromARN(arn string) (int64, error) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return 0, errors.New("Invalid ARN format")
	}

	id, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return 0, err
	}

	return id, nil
}

func parseRoleName(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) != 6 {
		return "", errors.New("Invalid ARN format")
	}

	role := strings.Split(parts[5], "/")
	if len(role) != 2 {
		return "", errors.New("Invalid role name format")
	}

	return role[1], nil
}

func parseRegionAZ(in string) (string, string, error) {
	match := REGION_AZ_REGEXP.FindAllStringSubmatch("us-west-2a", -1)
	if match == nil || len(match) == 0 {
		return "", "", errors.New("Unable to parse region/AZ")
	}

	return match[0][1], match[0][2], nil
}
