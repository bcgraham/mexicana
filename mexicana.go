package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"net/url"
	"strings"
	"time"
)

const SECONDS_BETWEEN_API_CALLS = 30
const MAX_WAIT_TIME = 10800000000000

type Alert struct {
	Line      string
	StopsAway int
}

type AlertRequestListener struct {
	incoming  chan Alert
	available bool
	done      chan bool
}

func (arl *AlertRequestListener) RequestNew(alert Alert, willAlert *bool) error {
	if arl.available {
		*willAlert = true
		arl.incoming <- alert
		arl.available = <-arl.done
	} else {
		*willAlert = false
	}
	return nil
}

func TrackAndAlert(incoming chan Alert, done chan bool, key string) {
	spark_token := Decrypt(key, SPARK_ACCESS_TOKEN)
	mta_api_key := Decrypt(key, MTA_API_KEY)
	for {
		<-incoming
		// for now, the incoming alert is discarded
		err := WaitForNeabyBus(mta_api_key, MAX_WAIT_TIME)
		if err != nil {
			log.Fatalf("WaitForNearbyBus returned error: %v", err)
		}
		PlayAlert(spark_token)
		done <- true
	}
}

const SPARK_ACCESS_TOKEN = "dd98377bd08cdc62b885d6dce21e10be20df70356d6c7edf7b4232cc4ed77d4178d7f856dcb0bf323d27fd0ab048ec9816df31fc19b718aac22dcd22bf2681c9"
const MTA_API_KEY = "c72835757ee6e939fdd5bfe76dc74f458f4e568856c93093b698bdfdc0b05ab4715f94dec953e743fb38916f1947861e45169fe8a866eb1a4573e880e5bd900e"

var key = flag.String("key", "", "key used to decrypt access token")

func main() {
	flag.Parse()
	arl := NewAlertRequestListener()
	go TrackAndAlert(arl.incoming, arl.done, *key)
	rpc.Register(arl)
	rpc.HandleHTTP()
	l, err := net.Listen("unix", "/tmp/mexicana.sock")
	if err != nil {
		log.Fatal("listen error: ", err)
	}
	defer l.Close()
	for {
		go rpc.Accept(l)
	}
}

func NewAlertRequestListener() (arl *AlertRequestListener) {
	incoming := make(chan Alert)
	done := make(chan bool)
	return &AlertRequestListener{incoming, false, done}
}

func WaitForNeabyBus(key string, maxWait time.Duration) error {
	start := time.Now()
	for time.Since(start) < maxWait {
		sr, err := getNewSiriResponse(key)
		if err != nil {
			return err
		}
		if len(sr.Siri.ServiceDelivery.StopMonitoringDelivery) > 0 {
			for _, msv := range sr.Siri.ServiceDelivery.StopMonitoringDelivery[0].MonitoredStopVisit {
				if int(msv.MonitoredVehicleJourney.MonitoredCall.Extensions.Distances.StopsFromCall) == 2 {
					return nil
				}
			}
		}
		fmt.Println("\n")
		time.Sleep(time.Second * SECONDS_BETWEEN_API_CALLS)
	}
	return fmt.Errorf("WaitForNearbyBus has exceeded its maximum wait time of %v.", maxWait)
}

func getNewSiriResponse(key string) (sr *SiriResponse, err error) {
	u := new(url.URL)
	u.Scheme = "https"
	u.Host = "bustime.mta.info"
	u.Path = "api/siri/stop-monitoring.json"

	v := &url.Values{}
	v.Set("key", key)
	v.Set("MonitoringRef", "551608")

	u.RawQuery = v.Encode()

	resp, err := http.Get(u.String())
	if err != nil {
		return sr, fmt.Errorf("Problem getting json data: %v", err)
	}
	sr = new(SiriResponse)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return sr, fmt.Errorf("Couldn't read the body of response from bustime.mta.info: %v", err)
	}
	resp.Body.Close()
	err = json.Unmarshal(body, &sr)
	if err != nil {
		return sr, fmt.Errorf("Problem unmarshaling response from bustime.mta.info: %v", err)
	}
	if sr.Siri.ServiceDelivery.VehicleMonitoringDelivery != nil {
		if sr.Siri.ServiceDelivery.VehicleMonitoringDelivery[0].ErrorCondition != nil {
			if sr.Siri.ServiceDelivery.VehicleMonitoringDelivery[0].ErrorCondition.OtherError != nil {
				return sr, fmt.Errorf("Response signaled there was an error interacting with the API: %v", sr.Siri.ServiceDelivery.VehicleMonitoringDelivery[0].ErrorCondition.OtherError.ErrorText)
			}
		}
	}
	return sr, nil
}

func PlayAlert(key string) {
	v := &url.Values{}
	v.Set("access_token", key)
	v.Set("args", "")
	resp, err := http.PostForm("https://api.spark.io/v1/devices/53ff77065075535138201387/proximity", *v)
	if err != nil {
		log.Fatalf("Problem posting: %v", err)
	}
	body := make([]byte, 1024)
	_, err = resp.Body.Read(body)
	if err != nil && err != io.EOF {
		log.Fatalf("Problem reading body: %v", err)
	}
	fmt.Printf("%s", body)
}

func Decrypt(key string, ciphertext string) string {
	access_token, _ := hex.DecodeString(ciphertext)
	key += strings.Repeat(" ", 16-(len(key)%16))
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		panic(err)
	}
	if len(access_token) < aes.BlockSize {
		panic("access_token too short")
	}
	iv := access_token[:aes.BlockSize]
	access_token = access_token[aes.BlockSize:]
	if len(access_token)%aes.BlockSize != 0 {
		panic("access_token is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(access_token, access_token)
	return strings.TrimSpace(fmt.Sprintf("%s", access_token))
}

type SiriResponse struct {
	Siri *Siri
}

type Siri struct {
	ServiceDelivery *ServiceDelivery
}

type ServiceDelivery struct {
	ResponseTimestamp         string
	StopMonitoringDelivery    []*StopMonitoringDelivery
	VehicleMonitoringDelivery []*VehicleMonitoringDelivery
}

type StopMonitoringDelivery struct {
	MonitoredStopVisit []*MonitoredStopVisit
}

type MonitoredStopVisit struct {
	MonitoredVehicleJourney MonitoredVehicleJourney
}

type MonitoredVehicleJourney struct {
	PublishedLineName string
	ProgressRate      string
	VehicleRef        string
	MonitoredCall     *MonitoredCall
}

type MonitoredCall struct {
	Extensions *Extensions
}

type Extensions struct {
	Distances *Distances
}

type Distances struct {
	PresentableDistance string
	StopsFromCall       float64
}

type VehicleMonitoringDelivery struct {
	ResponseTimestamp string
	ErrorCondition    *ErrorCondition
}

type ErrorCondition struct {
	OtherError *OtherError
}

type OtherError struct {
	ErrorText   string
	Description string
}
