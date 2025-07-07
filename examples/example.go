package main

import (
	"github.com/andrewhodel/go-ip-ac"
	"fmt"
)

func main() {

	var ip_ac ipac.Ipac

	// notify closure, use to send firewall notifications to admins
	ip_ac.NotifyClosure = func(message_id int, info string, ips []string) {

		// message_id is an int specifying the message id
		// info is a string about the event
		// ips is a list of ip addresses related to the event

	}

	ipac.Init(&ip_ac)

	// set authorization status for an IP
	// logout
	ipac.ModifyAuth(&ip_ac, "logout", "127.0.0.1")
	// invalid login credentials
	ipac.ModifyAuth(&ip_ac, "invalid_login", "127.0.0.1")
	// authorized (valid login credentials)
	ipac.ModifyAuth(&ip_ac, "valid_login", "127.0.0.1")

	// test authorization status for an IP
	// this needs to be called every time there is a new IP connection
	var status = ipac.TestIpAllowed(&ip_ac, "127.0.0.1")
	fmt.Printf("TestIpAllowed 127.0.0.1: %t\n", status)

	// test if you should warn users from an IP
	var warn = ipac.TestIpWarn(&ip_ac, "127.0.0.1")
	fmt.Printf("TestIpWarn 127.0.0.1: %t\n", warn)

	// return details for a specific ip address
	var ip_details = ipac.IpDetails(&ip_ac, "127.0.0.1")
	fmt.Printf("IpDetails 127.0.0.1: %+v\n", ip_details)

	select{}

}
