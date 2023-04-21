package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	am "github.com/shirou/gopsutil/net"
	yaml "gopkg.in/yaml.v2"
)

type Config struct {
	ConfigPath  string
	PortRange   string
	Ports       []string
	Addresses   []string
	OnInterface string
	MonitorType []string
	Interval    int
	OutputPath  string
}

type PacketSummaries struct {
	ip4 layers.IPv4
	tcp layers.TCP
	udp layers.UDP
}

type Yml struct {
	MonitorType []string `yaml:"monitor_type"`
	Interface   string   `yaml:"interface"`
	Interval    int      `yaml:"interval"`
	IPAddresses []string `yaml:"ip_addresses"`
	Path        string   `yaml:"path"`
	PortRange   string   `yaml:"port_range"`
	Ports       []string `yaml:"ports"`
}

func (m *PacketSummaries) isUDP() bool {
	return m.ip4.Protocol.String() == "UDP"
}
func (m *PacketSummaries) isTCP() bool {
	return m.ip4.Protocol.String() == "TCP"
}
func (m *PacketSummaries) isHttpRequest() bool {
	return m.tcp.PSH && m.tcp.ACK && m.ip4.Protocol.String() == "TCP"
}
func (m *PacketSummaries) isSYN() bool {
	return m.tcp.SYN && !m.tcp.ACK && m.ip4.Protocol.String() == "TCP"
}

var withPorts []int
var withAddresses []string
var beginPortRange int
var endPortRange int
var config Config
var reg = prometheus.NewRegistry()
var allAddress = false
var httpReqs = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Name: "HTTP_source_control_counter",
		Help: "Count requests from an ip address to ports on server",
	},
	[]string{"sourceIP", "destIP", "destPort", "protocol", "interface", "monitorType"},
)

func HandleError(er error) {
	log.Fatal(er)
}

func HandleMultipleError(input string, er error) {
	log.Fatal(errors.New(input + er.Error()))
}

func listInterfaces() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return errors.New("Khong the hien thi cac interfaces !")
	}
	fmt.Println("Danh sach cac interface:")
	for _, i := range ifaces {
		fmt.Println(" - ", i.Name)
	}
	return nil
}

func scanOpeningPortOnLocal() ([]int, error) {
	ports, er := am.Connections("inet")
	if er != nil {
		return nil, errors.New("Khong the quet cac port dang mo.")
	}
	var openingPorts []int
	for _, element := range ports {
		if element.Status == "LISTEN" {
			openingPorts = append(openingPorts, int(element.Laddr.Port))
		}
	}
	return openingPorts, nil
}

func validatePortRange(portRange string) error {
	if match, _ := regexp.MatchString("^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])"+
		"-([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", portRange); match {
		return nil
	}
	return errors.New("validatePortRange. Port range khong dung voi dinh dang: port-port")
}

func validatePorts(input []string) error {
	for _, value := range input {
		v, er := strconv.Atoi(value)
		if er != nil || !(1 <= v && v <= 65535) {
			return errors.New("validatePorts. Port " + value + " khong thoa dieu kien")
		}
	}
	return nil
}

func validateIpAddress(ip string) error {
	if strings.ToLower(ip) == "all" {
		return nil
	}
	if match, _ := regexp.MatchString("^((25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)\\.){3}(25[0-5]|(2[0-4]|1\\d|[1-9]|)\\d)$", ip); !match {
		return errors.New("validateIpAddress. IP: " + ip + " khong phai la 1 dia chi IP")
	}
	return nil
}

func validateMonitorType(listType []string) error {
	for _, v := range listType {
		if v != "HTTPRequest" && v != "SYNFlood" && v != "UDPFlood" {
			return errors.New("validateMonitorType. " + v + " khong dung")
		}
	}
	return nil
}

func digestPacket(info *PacketSummaries) {
	if info.isTCP() {
		dstPort := int64(info.tcp.DstPort)
		if info.isHttpRequest() && checkIfStringInList("HTTPRequest", config.MonitorType) {
			fmt.Println("check on: ", toInt(info.tcp.DstPort.String()))
			if checkIfPortInList(toInt(info.tcp.DstPort.String()), withPorts) && checkIfStringInList(info.ip4.DstIP.String(), withAddresses) {
				httpReqs.WithLabelValues(
					info.ip4.SrcIP.String(),
					info.ip4.DstIP.String(),
					strconv.FormatInt(dstPort, 10),
					info.ip4.Protocol.String(),
					config.OnInterface,
					"HTTPRequest").Inc()
			}
		}
		if info.isSYN() && checkIfStringInList("SYNFlood", config.MonitorType) {
			if checkIfPortInList(toInt(info.tcp.DstPort.String()), withPorts) && checkIfStringInList(info.ip4.DstIP.String(), withAddresses) {
				httpReqs.WithLabelValues(
					info.ip4.SrcIP.String(),
					info.ip4.DstIP.String(),
					strconv.FormatInt(dstPort, 10),
					info.ip4.Protocol.String(),
					config.OnInterface,
					"SYNFlood").Inc()
			}
		}
	}
	if info.isUDP() && checkIfStringInList("UDPFlood", config.MonitorType) {
		if checkIfPortInList(toInt(info.udp.DstPort.String()), withPorts) && checkIfStringInList(info.ip4.DstIP.String(), withAddresses) {
			httpReqs.WithLabelValues(
				info.ip4.SrcIP.String(),
				info.ip4.DstIP.String(),
				strconv.FormatInt(int64(info.udp.DstPort), 10),
				info.ip4.Protocol.String(),
				config.OnInterface,
				"UDPFlood").Inc()
		}
	}
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func toInt(input string) int {
	i, _ := strconv.Atoi(input)
	return i
}

func convertPortRange(portRange *string, beginPortRange *int, endPortRange *int) error {
	if validatePortRange(*portRange) == nil {
		list := strings.Split(*portRange, "-")
		first := toInt(list[0])
		last := toInt(list[1])
		if first < last {
			beginPortRange = &first
			endPortRange = &last
			return nil
		}
		beginPortRange = &last
		endPortRange = &first
		return nil
	} else {
		return errors.New("Port range sai cau truc yeu cau cau hinh lai!")
	}
}

func checkIfPortInList(port int, list []int) bool {
	for _, i := range list {
		if i == port {
			fmt.Println(port, " with ", i, " in ", list)
			return true
		}
	}
	return false
}
func checkIfStringInList(s string, l []string) bool {
	for _, a := range l {
		if a == s {
			return true
		}
	}
	return false
}

func writeMetricToFile(path string, registry *prometheus.Registry, vector *prometheus.GaugeVec) {
	for true {
		if er := prometheus.WriteToTextfile(path, registry); er != nil {
			HandleError(errors.New("Khong the ghi vao file: " + path))
		}
		httpReqs.Reset()
		time.Sleep(time.Duration(config.Interval) * time.Second)
	}
}

func scanOpeningPortWithRange() {
	for true {
		openningPorts, er := scanOpeningPortOnLocal()
		if er != nil {
			HandleError(er)
		}
		withPorts = []int{}
		for _, port := range openningPorts {
			if beginPortRange <= port && port <= endPortRange {
				withPorts = append(withPorts, port)
			}
		}
		fmt.Println(withPorts, ": are being scanned")
		time.Sleep(time.Duration(config.Interval) * time.Second)
	}
}

func init() {
	reg.MustRegister(httpReqs)
}

func catchingPacket() {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP

	dlc := gopacket.DecodingLayerContainer(gopacket.DecodingLayerArray(nil))

	dlc = dlc.Put(&eth)
	dlc = dlc.Put(&ip4)
	dlc = dlc.Put(&tcp)
	dlc = dlc.Put(&udp)

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
	decoded := []gopacket.LayerType{}

	if handle, err := pcap.OpenLive(config.OnInterface, 1600, true, pcap.BlockForever); err != nil {
		panic(err)
	} else if err := handle.SetBPFFilter(""); err != nil { // optional
		panic(err)
	} else {
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			parser.DecodeLayers(packet.Data(), &decoded)
			digestPacket(&PacketSummaries{ip4, tcp, udp})
		}
	}
}

func usingConfigFile() {
	yml := Yml{}
	yamlFile, er := ioutil.ReadFile(config.ConfigPath)
	if er != nil {
		HandleError(errors.New("Khong the mo file yaml"))
	}
	if er := yaml.Unmarshal(yamlFile, &yml); er != nil {
		HandleError(errors.New("Khong the chuyen noi dung yaml thanh config"))
	}
	config.Addresses = yml.IPAddresses
	config.PortRange = yml.PortRange
	config.Ports = yml.Ports
	config.OnInterface = yml.Interface
	config.MonitorType = yml.MonitorType
	config.Interval = yml.Interval
	config.OutputPath = yml.Path
}

func validateEverythings() {
	if len(config.PortRange) != 0 {
		if er := validatePortRange(config.PortRange); er != nil {
			HandleMultipleError("Validate. ", er)
			os.Exit(0)
		}
		if er := convertPortRange(&config.PortRange, &beginPortRange, &endPortRange); er != nil {
			HandleMultipleError("Validate. ", er)
		}
	}
	if len(config.Ports) != 0 {
		if er := validatePorts(config.Ports); er != nil {
			HandleMultipleError("Validate. ", er)
			os.Exit(0)
		}
	}
	if len(config.Ports)+len(config.PortRange) == 0 {
		HandleError(errors.New("Validate. Phai chi dinh ports hoac port range."))
		os.Exit(0)
	}
	for _, port := range config.Ports {
		p := toInt(port)
		if !checkIfPortInList(p, withPorts) {
			withPorts = append(withPorts, p)
		}
	}
	if len(config.Ports)+len(config.PortRange) == 0 {
		HandleError(errors.New("Validate. Phai chi dinh ports hoac port range."))
		os.Exit(0)
	}
	for _, ip := range config.Addresses {
		if er := validateIpAddress(ip); er != nil {
			HandleMultipleError("Validate. ", er)
			os.Exit(0)
		}
		withAddresses = append(withAddresses, ip)
	}
	if er := validateMonitorType(config.MonitorType); er != nil {
		HandleMultipleError("Validate. ", er)
		os.Exit(0)
	}
}

func yamlTemplateGenerater(generateYamlTemplate string) error {
	file, er := os.OpenFile(generateYamlTemplate, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0777)
	if er != nil {
		return er
	}
	defer file.Close()
	enc := yaml.NewEncoder(file)
	err := enc.Encode(Yml{
		MonitorType: []string{"HTTPRequest", "SYNFlood", "UDPFlood"},
		Interface:   "lo",
		Interval:    10,
		IPAddresses: []string{"127.0.0.1", "192.168.1.170"},
		Path:        "/path/to/file/filename.prom",
		Ports:       []string{"or using this: ", "80", "90", "100"},
		PortRange:   "using this: 1-65000",
	})
	if err != nil {
		return err
	}
	return nil
}

func getArgs() {
	ports := flag.String("ports", "", "Quet tren cac port ")
	addresses := flag.String("addresses", "127.0.0.1", "Report cac goi tin co destination den IP")
	monitorType := flag.String("monitor-type", "HTTPRequest", "Loai goi tin se duoc dem so luong")
	listInterfacesBool := flag.Bool("list-interfaces", false, "Hien cac interface dang co tren server")
	generateYamlTemplate := flag.String("generate-yaml-template", "template_config.yml", "Tao 1 file yaml config mau")
	flag.StringVar(&config.ConfigPath, "config", "", "Su dung file config thay cho Agrs")
	flag.StringVar(&config.PortRange, "port-range", "", "Quet tren cac port trong range")
	flag.StringVar(&config.OnInterface, "interface", "lo", "Quet tren duy nhat 1 interface")
	flag.StringVar(&config.OutputPath, "output-path", "metrics.prom", "Xuat metrics thanh 1 file")
	flag.IntVar(&config.Interval, "interval", 3, "Thoi gian chuong trinh reset va ghi vao file ")
	flag.Parse()
	config.Addresses = strings.Split(*addresses, ",")
	config.MonitorType = strings.Split(*monitorType, ",")
	if isFlagPassed("ports") {
		config.Ports = strings.Split(*ports, ",")
	}
	if *listInterfacesBool {
		if er := listInterfaces(); er != nil {
			HandleError(er)
		}
		os.Exit(0)
	}
	if isFlagPassed("generate-yaml-template") {
		yamlTemplateGenerater(*generateYamlTemplate)
		os.Exit(0)
	}
}

func preparing() {
	getArgs()
	if isFlagPassed("config") {
		usingConfigFile()
	}
	fmt.Println(config)
	validateEverythings()
}

func controller() {
	preparing()
	if len(config.PortRange) != 0 {
		fmt.Println("Creating port-range Scanner")
		go scanOpeningPortWithRange()
	}
	fmt.Println("Scanning on: ", withPorts)
	go writeMetricToFile(config.OutputPath, reg, httpReqs)
	catchingPacket()
}

func main() {
	// Goi ham quan ly cac concurrent
	controller()
}
