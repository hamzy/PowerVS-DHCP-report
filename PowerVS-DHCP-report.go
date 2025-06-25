// Copyright 2025 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// (cd PowerVS-DHCP-report/; /bin/rm go.*; go mod init example/user/PowerVS-DHCP-report; go mod tidy)
// (cd PowerVS-DHCP-report/; echo "vet:"; go vet || exit 1; echo "build:"; go build -ldflags="-X main.version=$(git describe --always --long --dirty) -X main.release=$(git describe --tags --abbrev=0)" -o PowerVS-DHCP-report *.go || exit 1; echo "run:"; ./PowerVS-DHCP-report -apiKey "$(cat /var/run/powervs-ipi-cicd-secrets/powervs-creds/IBMCLOUD_API_KEY)" -shouldDebug true -crn ...)

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"math"
	gohttp "net/http"
	"os"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/golang-jwt/jwt"

	"github.com/IBM-Cloud/bluemix-go"
	"github.com/IBM-Cloud/bluemix-go/authentication"
	"github.com/IBM-Cloud/bluemix-go/crn"
	"github.com/IBM-Cloud/bluemix-go/http"
	"github.com/IBM-Cloud/bluemix-go/rest"
	bxsession "github.com/IBM-Cloud/bluemix-go/session"

	"github.com/IBM-Cloud/power-go-client/clients/instance"
	"github.com/IBM-Cloud/power-go-client/ibmpisession"
	"github.com/IBM-Cloud/power-go-client/power/models"

	"github.com/IBM/go-sdk-core/v5/core"

	"github.com/sirupsen/logrus"

	"k8s.io/apimachinery/pkg/util/wait"
)

var (
	// Replaced with:
	//   -ldflags="-X main.version=$(git describe --always --long --dirty)"
	version        = "undefined"
	release        = "undefined"

	shouldDebug    = false
	shouldDelete   = false
	log            *logrus.Logger
	defaultTimeout = 5 * time.Minute
	// Map of regions to a zone
	Regions      = map[string][]string{
		"dal":      { "dal10",   "dal12"   },
		"eu-de":    { "eu-de-1", "eu-de-2" },
		"eu-gb":    { "eu-gb",   },
		"lon":      { "lon04",   "lon06"   },
		"mad":      { "mad02",   "mad04"   },
		"mon":      { "mon01"    },
		"osa":      { "osa21"    },
		"sao":      { "sao01",   "sao04"   },
		"syd":      { "syd04",   "syd05"   },
		"tok":      { "tok04"    },
		"tor":      { "tor01"    },
		"us-east":  { "us-east"  },
		"us-south": { "us-south" },
		"wdc":      { "wdc06",   "wdc07"   },
	}
)

func mapZoneToRegion(zone string) string {
	var (
		foundRegion string
	)

	for regionName, zoneValues := range Regions {
		for _, z := range zoneValues {
			if z == zone {
				foundRegion = regionName
			}
		}
	}

	return foundRegion
}

func contextWithTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), defaultTimeout)
}

func leftInContext(ctx context.Context) time.Duration {
	deadline, ok := ctx.Deadline()
	if !ok {
		return math.MaxInt64
	}

	duration := time.Until(deadline)

	return duration
}

type User struct {
	ID         string
	Email      string
	Account    string
	cloudName  string
	cloudType  string
	generation int
}

func fetchUserDetails(bxSession *bxsession.Session, generation int) (*User, error) {
	var (
		bluemixToken string
	)

	config := bxSession.Config
	user := User{}

	if strings.HasPrefix(config.IAMAccessToken, "Bearer") {
		bluemixToken = config.IAMAccessToken[7:len(config.IAMAccessToken)]
	} else {
		bluemixToken = config.IAMAccessToken
	}

	token, err := jwt.Parse(bluemixToken, func(token *jwt.Token) (interface{}, error) {
		return "", nil
	})
	if err != nil && !strings.Contains(err.Error(), "key is of invalid type") {
		return &user, err
	}

	claims := token.Claims.(jwt.MapClaims)
	if email, ok := claims["email"]; ok {
		user.Email = email.(string)
	}
	user.ID = claims["id"].(string)
	user.Account = claims["account"].(map[string]interface{})["bss"].(string)
	iss := claims["iss"].(string)
	if strings.Contains(iss, "https://iam.cloud.ibm.com") {
		user.cloudName = "bluemix"
	} else {
		user.cloudName = "staging"
	}
	user.cloudType = "public"
	user.generation = generation

	log.Debugf("user.ID         = %v", user.ID)
	log.Debugf("user.Email      = %v", user.Email)
	log.Debugf("user.Account    = %v", user.Account)
	log.Debugf("user.cloudType  = %v", user.cloudType)
	log.Debugf("user.generation = %v", user.generation)

	return &user, nil
}

func createPiSession(apiKey string, region string, zone string) (*ibmpisession.IBMPISession, error) {
	var (
		bxSession             *bxsession.Session
		tokenProviderEndpoint string = "https://iam.cloud.ibm.com"
		authenticator         *core.IamAuthenticator
		piOptions             *ibmpisession.IBMPIOptions
		piSession             *ibmpisession.IBMPISession
		err                   error
	)

	bxSession, err = bxsession.New(&bluemix.Config{
		BluemixAPIKey:         apiKey,
		TokenProviderEndpoint: &tokenProviderEndpoint,
		Debug:                 false,
	})
	if err != nil {
		return nil, fmt.Errorf("Error bxsession.New: %v", err)
	}
	log.Debugf("bxSession = %v", bxSession)

	tokenRefresher, err := authentication.NewIAMAuthRepository(bxSession.Config, &rest.Client{
		DefaultHeader: gohttp.Header{
			"User-Agent": []string{http.UserAgent()},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("Error authentication.NewIAMAuthRepository: %v", err)
	}
	log.Debugf("tokenRefresher = %v", tokenRefresher)
	err = tokenRefresher.AuthenticateAPIKey(bxSession.Config.BluemixAPIKey)
	if err != nil {
		return nil, fmt.Errorf("Error tokenRefresher.AuthenticateAPIKey: %v", err)
	}

	user, err := fetchUserDetails(bxSession, 2)
	if err != nil {
		return nil, fmt.Errorf("Error fetchUserDetails: %v", err)
	}

	authenticator = &core.IamAuthenticator{
		ApiKey: apiKey,
	}
	piOptions = &ibmpisession.IBMPIOptions{
		Authenticator: authenticator,
		Debug:         false,
		Region:        region,
		URL:           fmt.Sprintf("https://%s.power-iaas.cloud.ibm.com", region),
		UserAccount:   user.Account,
		Zone:          zone,
	}

	piSession, err = ibmpisession.NewIBMPISession(piOptions)
	if err != nil {
		return nil, fmt.Errorf("Error ibmpisession.New: %v", err)
	}
	log.Debugf("piSession = %v", piSession)

	return piSession, nil
}

func createDhcpClient(piSession *ibmpisession.IBMPISession, GUID string) (*instance.IBMPIDhcpClient, error) {
	var (
		dhcpClient *instance.IBMPIDhcpClient
	)

	dhcpClient = instance.NewIBMPIDhcpClient(context.Background(), piSession, GUID)
	log.Debugf("createDhcpClient: dhcpClient = %v", dhcpClient)

	if dhcpClient == nil {
		return nil, fmt.Errorf("Error: createDhcpClient has a nil dhcpClient!")
	}

	return dhcpClient, nil
}

func createInstanceClient(piSession *ibmpisession.IBMPISession, GUID string) (*instance.IBMPIInstanceClient, error) {
	var (
		instanceClient *instance.IBMPIInstanceClient
	)

	instanceClient = instance.NewIBMPIInstanceClient(context.Background(), piSession, GUID)
	log.Debugf("createInstanceClient: instanceClient = %v", instanceClient)

	if instanceClient == nil {
		return nil, fmt.Errorf("Error: createInstanceClient has a nil instanceClient!")
	}
	return instanceClient, nil
}

func findDhcpServers(dhcpClient *instance.IBMPIDhcpClient, instanceClient *instance.IBMPIInstanceClient) error {
	var (
		dhcpServers      models.DHCPServers
		dhcpServer       *models.DHCPServer
//		dhcpServerDetail *models.DHCPServerDetail
		instance         *models.PVMInstance
		err              error
	)

	dhcpServers, err = dhcpClient.GetAll()
	if err != nil {
		return fmt.Errorf("Error: dhcpClient.GetAll returns %v", err)
	}

	for _, dhcpServer = range dhcpServers {
		if dhcpServer.ID == nil {
			log.Debugf("findDhcpServers: SKIP nil(ID)")
			continue
		}
		if dhcpServer.Network == nil {
			log.Debugf("findDhcpServers: SKIP %s nil(Network)", *dhcpServer.ID)
			continue
		}

		var field1, field2 string

		if dhcpServer.ID == nil {
			field1 = "nil-ID"
		} else {
			field1 = *dhcpServer.ID
		}
		if dhcpServer.Network.Name == nil {
			field2 = "nil-Network-Name"
		} else {
			field2 = *dhcpServer.Network.Name
		}

		fmt.Printf("findDhcpServers: FOUND %s %s\n", field1, field2)

//		dhcpServerDetail, err = dhcpClient.Get(*dhcpServer.ID)
//		if err != nil {
//			return fmt.Errorf("Error: dhcpClient.Get returns %v", err)
//		}
//		log.Debugf("findDhcpServers: dhcpServerDetail = %+v", dhcpServerDetail)

		if dhcpServer.ID != nil {
			instance, err = instanceClient.Get(*dhcpServer.ID)
			if err != nil {
				return fmt.Errorf("Error: instanceClient.Get(%s) returns %v", *dhcpServer.ID, err)
			}
			log.Debugf("findDhcpServers: instance = %+v", instance)

			// Don't print out external IP addresses
			for _, address := range instance.Addresses {
				address.ExternalIP = ""
			}
			for _, address := range instance.Networks {
				address.ExternalIP = ""
			}

			spew.Dump(instance)
		}

		if shouldDelete {
			err = dhcpClient.Delete(*dhcpServer.ID)
			if err != nil {
				fmt.Printf("Warning: dhcpClient.Delete(%s) returns %v\n", *dhcpServer.ID, err)
				continue
//				return fmt.Errorf("Error: dhcpClient.Delete(%s) returns %v", *dhcpServer.ID, err)
			}

			err = waitForDhcpServerDelete(dhcpClient, *dhcpServer.ID)
			if err != nil {
				log.Fatalf("Error: waitForDhcpServerDelete returns %v", err)
				return err
			}
		}
	}

	return nil
}

func waitForDhcpServerDelete(dhcpClient *instance.IBMPIDhcpClient, id string) error {
	var (
		ctx    context.Context
		cancel context.CancelFunc
		err    error
	)

	ctx, cancel = context.WithTimeout(context.Background(), 15 * time.Minute)
	defer cancel()

	backoff := wait.Backoff{
		Duration: 15 * time.Second,
		Factor:   1.1,
		Cap:      leftInContext(ctx),
		Steps:    math.MaxInt32}
	err = wait.ExponentialBackoffWithContext(ctx, backoff, func(context.Context) (bool, error) {
		var (
			detail *models.DHCPServerDetail

			err2 error
		)

		detail, err2 = dhcpClient.Get(id)
		if err2 != nil {
			if strings.Contains(err2.Error(), "dhcp server does not exist") {
				return true, nil
			}
			return true, err2
		}
		log.Debugf("waitForDhcpServerDelete: Status = %s", *detail.Status)
		switch *detail.Status {
		case "ACTIVE":
			return false, nil
		case "BUILD":
			return false, nil
		default:
			return true, fmt.Errorf("waitForDhcpServerDelete: unknown state: %s", *detail.Status)
		}
	})
	if err != nil {
		log.Fatalf("Error: waitForDhcpServerDelete: ExponentialBackoffWithContext returns %v", err)
		return err
	}

	return nil
}

func main() {
	var (
		out                 io.Writer
		ptrVersion          *bool
		ptrApiKey           *string
		ptrCrn              *string
		ptrShouldDebug      *string
		ptrShouldDelete     *string
		crnStruct           crn.CRN
		region              string
		piSession           *ibmpisession.IBMPISession
		dhcpClient          *instance.IBMPIDhcpClient
		instanceClient      *instance.IBMPIInstanceClient
		err                 error
	)

	ptrVersion = flag.Bool("version", false, "print version information")
	ptrApiKey = flag.String("apiKey", "", "Your IBM Cloud API key")
	ptrCrn = flag.String("crn", "", "The Service Instance CRN to use")
	ptrShouldDebug = flag.String("shouldDebug", "false", "Should output debug output")
	ptrShouldDelete = flag.String("shouldDelete", "false", "Should delete resources")

	flag.Parse()

	if *ptrVersion {
		fmt.Printf("version = %v\nrelease = %v\n", version, release)
		os.Exit(0)
	}

	switch strings.ToLower(*ptrShouldDebug) {
	case "true":
		shouldDebug = true
	case "false":
		shouldDebug = false
	default:
		err = fmt.Errorf("Error: shouldDebug is not true/false (%s)\n", *ptrShouldDebug)
		fmt.Println(err)
		os.Exit(1)
	}

	if shouldDebug {
		out = os.Stderr
	} else {
		out = io.Discard
	}
	log = &logrus.Logger{
		Out: out,
		Formatter: new(logrus.TextFormatter),
		Level: logrus.DebugLevel,
	}

	switch strings.ToLower(*ptrShouldDelete) {
	case "true":
		shouldDelete = true
	case "false":
		shouldDelete = false
	default:
		err = fmt.Errorf("Error: shouldDelete is not true/false (%s)\n", *ptrShouldDelete)
		fmt.Println(err)
		os.Exit(1)
	}

	if *ptrApiKey == "" {
		fmt.Println("Error: No API key set, use -apiKey")
		os.Exit(1)
	}
	if *ptrCrn == "" {
		fmt.Println("Error: No CRN set, use -region")
		os.Exit(1)
	}

	log.Debugf("version = %v\nrelease = %v", version, release)
	log.Debugf("Begin")

	crnStruct, err = crn.Parse(*ptrCrn)
	if err != nil {
		fmt.Printf("Error: crn.Parse(%s) returns %s\n", *ptrCrn, err)
		os.Exit(1)
	}
	log.Debugf("crnStruct = %+v", crnStruct)

	// The CRN only has a region which is a PowerVS zone.  So also find a PowerVS region.
	region = mapZoneToRegion(crnStruct.Region)

	if region == "" {
		fmt.Printf("Error: Could not map zone %s\n", crnStruct.Region)
		os.Exit(1)
	}

	log.Debugf("Handling ServiceInstance %s in region %s and zone %s\n", crnStruct.ServiceInstance, region, crnStruct.Region)

	piSession, err = createPiSession(*ptrApiKey, region, crnStruct.Region)
	if err != nil {
		log.Fatalf("Error: createPiSession returns %v", err)
		os.Exit(1)
	}

	dhcpClient, err = createDhcpClient(piSession, crnStruct.ServiceInstance)
	if err != nil {
		log.Fatalf("Error: createDhcpClient returns %v", err)
		os.Exit(1)
	}
	log.Debugf("dhcpClient = %v", dhcpClient)

	instanceClient, err = createInstanceClient(piSession, crnStruct.ServiceInstance)
	if err != nil {
		log.Fatalf("Error: createInstanceClient returns %v", err)
		os.Exit(1)
	}
	log.Debugf("instanceClient = %v", instanceClient)

	err = findDhcpServers(dhcpClient, instanceClient)
	if err != nil {
		log.Fatalf("Error: findDhcpServers returns %v", err)
		os.Exit(1)
	}
}
