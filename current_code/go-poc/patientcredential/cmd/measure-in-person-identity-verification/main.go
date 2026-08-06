package main

import (
	"encoding/json"
	"flag"
	"fmt"
	pc "github.com/nasif2005/healthcare-specific-idm/go-poc/patientcredential"
	"log"
	"os"
)

func main() {
	n := flag.Int("iterations", 30, "number of measured workflow repetitions")
	out := flag.String("output", "", "optional JSON output file")
	flag.Parse()
	r, e := pc.MeasureInPersonIdentityVerification(*n)
	if e != nil {
		log.Fatal(e)
	}
	b, e := json.MarshalIndent(r, "", "  ")
	if e != nil {
		log.Fatal(e)
	}
	if *out == "" {
		fmt.Println(string(b))
		return
	}
	if e = os.WriteFile(*out, append(b, '\n'), 0o600); e != nil {
		log.Fatal(e)
	}
}
