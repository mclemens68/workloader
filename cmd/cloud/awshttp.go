package cloud

import (
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func checkForNil(str *string) string {
	if str == nil {
		return ""
	}
	return *str
}

func awsHTTP(region string, keyMap map[string]string) map[string]cloudData {

	//If you dont put in UserID and Secret (optionally Token) it will try to look for the credentials in the
	// location where AWS installs a credential file - ~/.aws/credentials or c:/users/%userid%/.aws/credentials
	var sess *session.Session
	if awsUserID == "" {
		sess, _ = session.NewSession(&aws.Config{
			Region: aws.String(region),
		})
	} else if awsSecret != "" {
		sess, _ = session.NewSession(&aws.Config{
			Region:      aws.String(region),
			Credentials: credentials.NewStaticCredentials(awsUserID, awsSecret, awsToken),
		})
	}

	//Call the EC2 API to get the instance info
	ec2Svc := ec2.New(sess)
	result, err := ec2Svc.DescribeInstances(nil)
	if err != nil {
		fmt.Println("Error", err)
	}

	//Cycle through all the reservations for all arrays in that reservation
	allVMs := make(map[string]cloudData)
	for _, res := range result.Reservations {
		for _, instance := range res.Instances {

			// Get all the tags for the instance and compare against keymap values to see if there is a match of PCE RAEL labeks
			var tmpName string
			tmptag := make(map[string]string)
			for _, tag := range instance.Tags {
				if *tag.Key == "Name" {
					tmpName = *tag.Value
				}
				if keyMap[*tag.Key] != "" {
					tmptag[keyMap[*tag.Key]] = *tag.Value
				}
			}
			tmpInstance := cloudData{Name: tmpName, VMID: *instance.InstanceId, Tags: tmptag, Location: region, OsType: ""}

			//Capture all the instances interfaces and get all IPs for those interfaces.
			for _, intf := range instance.NetworkInterfaces {
				var tmpawsintf Interface
				if intf.Association != nil {
					tmpawsintf.PublicIP = *intf.Association.PublicIp
					tmpawsintf.PublicDNS = *intf.Association.PublicDnsName
				}
				if intf.PrivateDnsName != nil {
					tmpawsintf.PrivateDNS = *intf.PrivateDnsName
				}
				for _, privip := range intf.PrivateIpAddresses {
					tmpawsintf.PrivateIP = append(tmpawsintf.PrivateIP, *privip.PrivateIpAddress)
				}
				tmpInstance.Interfaces = append(tmpInstance.Interfaces, tmpawsintf)

			}
			allVMs[*instance.InstanceId] = tmpInstance

		}
	}
	return allVMs

}
