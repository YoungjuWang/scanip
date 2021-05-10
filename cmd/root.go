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
	"bytes"
	"fmt"
	"net"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	homedir "github.com/mitchellh/go-homedir"
	"github.com/spf13/viper"
	fastping "github.com/tatsushid/go-fastping"
)

var cidr string
var cfgFile string
var all bool
var used bool
var unused bool

func Hosts(cidr string) map[string]string {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}

	ips := make(map[string]string)
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips[ip.String()] = "X"
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "scanip",
	Short:   "scan used/unused ip addresses",
	Long:    `Using ICMP. Check used/unused ip addresses. If your system block ICMP packet, "scanip" cannot work well`,
	Example: "scanip -c 192.168.0.0/24",
	Run: func(cmd *cobra.Command, args []string) {
		ipList := Hosts(cidr)

		p := fastping.NewPinger()

		for ip := range ipList {
			err := p.AddIP(ip)
			if err != nil {
				fmt.Println(err)
				os.Exit(3)
			}
		}

		p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
			ipList[addr.String()] = "O"
		}
		p.OnIdle = func() {
			fmt.Printf("IP_Address\t\tUsed\n")
			fmt.Printf("=================================\n")
		}
		err := p.Run()
		if err != nil {
			fmt.Println(err)
		}

		var keys []net.IP
		for k := range ipList {
			keys = append(keys, net.ParseIP(k))
		}
		sort.Slice(keys, func(i, j int) bool {
			return bytes.Compare(keys[i], keys[j]) < 0
		})

		for _, key := range keys {
			switch {
			case used:
				if ipList[key.String()] == "O" {
					fmt.Printf("%s\t\t%s\n", key, ipList[key.String()])
				}
			case unused:
				if ipList[key.String()] == "X" {
					fmt.Printf("%s\t\t%s\n", key, ipList[key.String()])
				}
			default:
				fmt.Printf("%s\t\t%s\n", key, ipList[key.String()])
			}
		}
		fmt.Printf("\nCheck Finished.\n")
	},
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}

func init() {
	cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.

	//rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.scanip.yaml)")
	rootCmd.Flags().StringVarP(&cidr, "cidr", "c", "", "Network CIDR (required)")
	rootCmd.MarkFlagRequired("cidr")
	rootCmd.Flags().BoolVarP(&all, "all", "a", true, "Print all addresses")
	rootCmd.Flags().BoolVarP(&used, "used", "o", false, "Print used addresses")
	rootCmd.Flags().BoolVarP(&unused, "unused", "x", false, "Print unused addresses")

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfgFile != "" {
		// Use config file from the flag.
		viper.SetConfigFile(cfgFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		cobra.CheckErr(err)

		// Search config in home directory with name ".scanip" (without extension).
		viper.AddConfigPath(home)
		viper.SetConfigName(".scanip")
	}

	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}
