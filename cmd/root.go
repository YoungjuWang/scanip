/*
Copyright © 2021 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package cmd

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	fastping "github.com/tatsushid/go-fastping"
)

// IPList 는 결과 값들을 담을 struct.
type IPList struct {
	ip    string
	state string
}

// GetIPList 는 CIDR 값을 받아서 IP List를 IpList struct에 넘겨줌.
func GetIPList(cidr string) []IPList {
	// convert string to cidr > ipv4Net
	_, ipv4Net, err := net.ParseCIDR(cidr)
	if err != nil {
		fmt.Println(err)
		os.Exit(3)
	}

	// convert ipv4Net address to uint32
	// network is BigEndian
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)

	// Get Start IP, Finish IP
	start := binary.BigEndian.Uint32(ipv4Net.IP)
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	il := []IPList{}
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		pair := IPList{}
		if i == start {
			pair = IPList{ip.String(), "Network Address"}
		} else if i == finish {
			pair = IPList{ip.String(), "Broadcast Address"}
		} else {
			pair = IPList{ip.String(), "X"}
		}
		il = append(il, pair)
	}

	return il
}

// IPLIst 및 State 출력
func PrintIPList(il []IPList, used bool, unused bool) {
	fmt.Printf("IP_Address\t\tUsed\n")
	fmt.Printf("=================================\n")
	for _, ls := range il {
		switch {
		case used:
			if ls.state == "O" || ls.state == "Network Address" || ls.state == "Broadcast Address" {
				fmt.Printf("%s\t\t%s\n", ls.ip, ls.state)
			}
		case unused:
			if ls.state == "X" {
				fmt.Printf("%s\t\t%s\n", ls.ip, ls.state)
			}
		default:
			fmt.Printf("%s\t\t%s\n", ls.ip, ls.state)
		}
	}
}

var (
	cidr   string
	all    bool
	used   bool
	unused bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "scanip",
	Short:   "scan used/unused ip addresses",
	Long:    `Using ICMP. Check used/unused ip addresses. If your system block ICMP packet, "scanip" cannot work well`,
	Example: "scanip -c 192.168.0.0/24",
	Run: func(cmd *cobra.Command, args []string) {
		il := GetIPList(cidr)
		p := fastping.NewPinger()

		// ping 목록에 ip들을 전달
		for _, ls := range il {
			err := p.AddIP(ls.ip)
			if err != nil {
				fmt.Println(err)
				os.Exit(4)
			}
		}

		// ping 성공 시 ip의 status를 update
		p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
			for i := range il {
				if il[i].ip == addr.String() {
					il[i].state = "O"
				}
			}
		}

		// ping Check가 끝난 후 실행될 내용
		p.OnIdle = func() {
			PrintIPList(il, used, unused)
		}

		// ping 실행
		err := p.Run()
		if err != nil {
			fmt.Println(err)
			os.Exit(11)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	//cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Network CIDR (required)")
	rootCmd.MarkFlagRequired("cidr")
	rootCmd.Flags().BoolVarP(&all, "all", "a", true, "Print all addresses")
	rootCmd.Flags().BoolVarP(&used, "used", "o", false, "Print used addresses")
	rootCmd.Flags().BoolVarP(&unused, "unused", "x", false, "Print unused addresses")
}
