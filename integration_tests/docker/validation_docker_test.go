package docker

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// CaseInsensitiveContains in string
func CaseInsensitiveContains(s, substr string) bool {
	s, substr = strings.ToUpper(s), strings.ToUpper(substr)
	return strings.Contains(s, substr)
}

func runcmd(cmd string) []byte {

	log.Println("commande :", cmd)
	out, err := exec.Command("bash", "-c", cmd).Output()
	if err != nil {
		log.Fatal(string(out), err)
	}
	log.Println("resultat :", string(out))
	if CaseInsensitiveContains(string(out), "error") {
		//log.Fatal("Validation plan Failed => ", string(out))
		log.Println("Validation plan Failed => ", string(out))
	}
	return out
}

func stopBrokerd() {
	log.Println("docker rm -f brokerd-test")
	cmdStr := "docker rm -f  brokerd-test"
	runcmd(cmdStr)
}

func launchBroker() {
	var idCont string
	cmdStr := "docker ps -a -f 'status=exited' -f 'name=brokerd-build' | tail -n +2 | awk '{print $1 }'"
	idContainer := runcmd(cmdStr)
	str := fmt.Sprintf("%s", idContainer)
	idCont = strings.Trim(str, "\n")
	// if build necessary
	if len(strings.TrimSpace(idCont)) == 0 {
		launchBrokerdBuild()
	}
	launchBrokerdTest()
}

func launchDockerExec(mode string, delay time.Duration, command string) []byte {
	const blank = " "
	const dirBroker = "/usr/local/safescale/bin/"
	cmdStr := "docker exec -" + mode + " brokerd-test " + dirBroker + command
	out := runcmd(cmdStr)
	time.Sleep(delay * time.Second)
	return out
}

func launchBrokerdBuild() {
	cmdStr := "docker run --name brokerd-build "
	cmdStr += "-v broker-binaries:/usr/local/safescale "
	cmdStr += "-e http_proxy=$http_proxy -e https_proxy=$https_proxy -e SAFESCALE_METADATA_SUFFIX=pc "
	cmdStr += "--entrypoint \"\" safescale:latest /bin/bash -c /opt/build-safescale.sh"
	runcmd(cmdStr)
}

func launchBrokerdTest() {
	cmdStr := "docker run --name brokerd-test -d "
	home := os.Getenv("HOME")
	cmdStr += "-v " + home + "/.safescale/tenants-Save.toml:/tmp/tenants.toml "
	cmdStr += "-v broker-binaries:/usr/local/safescale "
	cmdStr += "-e SAFESCALE_METADATA_SUFFIX=pc "
	cmdStr += "--entrypoint /usr/local/safescale/bin/brokerd "
	cmdStr += "safescale:latest"
	log.Println("commande :", cmdStr)
	_, err := exec.Command("bash", "-c", cmdStr).Output()
	if err != nil {
		if CaseInsensitiveContains(err.Error(), "exit status 125") {
			log.Println("Container brokerd-test already started will be removed ")
			runcmd("docker rm -f brokerd-test")
			runcmd(cmdStr)
		}
	}

}

func launchClient(tenant string) {
	const detach = "d"
	const intera = "i"
	var delay time.Duration = 10
	launchDockerExec(intera, delay, "broker tenant list")
	launchDockerExec(intera, delay, "broker tenant set "+tenant)
	launchDockerExec(intera, delay, "broker tenant get")

	if tenant == "TestFlexibleEngine" {
		out := launchDockerExec(intera, delay, "broker network  create networktest --cpu 2 --ram 4 --os \"OBS_U_Ubuntu_16.04\" --cidr \"192.168.1.0/24\" ")
		if CaseInsensitiveContains(string(out), "already exists") {
			launchDockerExec(intera, delay, "broker host delete gw-networktest")
			launchDockerExec(intera, delay, "broker network  delete  networktest")
			launchDockerExec(intera, delay, "broker network  create networktest --cpu 2 --ram 4 --os \"OBS_U_Ubuntu_16.04\" --cidr \"192.168.1.0/24\" ")
		}
	}

	if tenant == "TestOvh" {
		out := launchDockerExec(intera, delay, "broker network  create networktest  ")
		if CaseInsensitiveContains(string(out), "already exists") {
			launchDockerExec(intera, delay, "broker host delete gw-networktest")
			launchDockerExec(intera, delay, "broker network  delete  networktest")
			launchDockerExec(intera, delay, "broker network  create networktest   ")
		}

	}
	launchDockerExec(intera, delay, "broker network list  ")
	if tenant == "TestFlexibleEngine" {
		launchDockerExec(intera, delay, "broker host  create hostest1  --cpu 4 --ram 50 networktest ")
		launchDockerExec(intera, delay, "broker host  create hostest2  --cpu 4 --ram 50 networktest ")
	}
	if tenant == "TestOvh" {
		launchDockerExec(intera, delay, "broker host create hostest1 networktest ")
		launchDockerExec(intera, delay, "broker host create hostest2 networktest ")

	}

	launchDockerExec(intera, delay, "broker nas  create bnastest hostest1")
	launchDockerExec(intera, delay, "broker nas  mount bnastest hostest2")
	launchDockerExec(intera, delay, "broker nas inspect bnastest")
	launchDockerExec(intera, delay, "broker nas  list ")
	launchDockerExec(intera, delay, "broker nas  umount bnastest hostest2")
	launchDockerExec(intera, delay, "broker nas delete bnastest ")
	launchDockerExec(intera, delay, "broker volume  create volumetest")
	launchDockerExec(intera, delay, "broker volume  attach  volumetest hostest1 ")
	launchDockerExec(intera, delay, "broker volume  inspect volumetest")
	launchDockerExec(intera, delay, "broker volume  detach  volumetest hostest1 ")
	launchDockerExec(intera, delay, "broker volume  inspect volumetest")
	launchDockerExec(intera, delay, "broker volume  delete volumetest")
	launchDockerExec(intera, delay, "broker host list")
	launchDockerExec(detach, delay, "broker ssh connect hostest1")
	launchDockerExec(intera, delay, "broker host inspect hostest1")
	launchDockerExec(intera, delay, "broker host delete hostest1")
	launchDockerExec(intera, delay, "broker host delete hostest2")

	launchDockerExec(intera, delay, "broker host delete gw-networktest")
	launchDockerExec(intera, delay, "broker network  delete  networktest")

}

func Main() {
	start := time.Now()
	log.Println("https_proxy:", os.Getenv("https_proxy"))
	log.Println("https_proxy:", os.Getenv("https_proxy"))
	log.Println(" ")
	log.Println("**** LAUNCH BROKER ****")
	launchBroker()
	log.Println("**** LAUNCH BROKER STARTED****")
	log.Println(" ")

	log.Println("**** LAUNCH CLIENT TESTS START  ****")
	launchClient("TestOvh")
	//launchClient("TestFlexibleEngine")
	log.Println("**** LAUNCH CLIENT TESTS FINISH  ****")
	log.Println(" ")
	log.Println("**** STOP BROKERD ****")
	stopBrokerd()
	elapsed := time.Since(start)
	log.Printf("Test took %s", elapsed)
}
