// Command measure-pseudonym-token-issuance writes repeatable POC metrics.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	pc "github.com/nasif2005/healthcare-specific-idm/go-poc/patientcredential"
)

func main() {
	iterations := flag.Int("iterations", 30, "number of measured workflow repetitions")
	output := flag.String("output", "", "optional JSON output file; defaults to standard output")
	flag.Parse()
	result, err := pc.MeasurePseudonymTokenIssuance(*iterations)
	if err != nil {
		log.Fatal(err)
	}
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	if *output == "" {
		fmt.Println(string(data))
		return
	}
	if err = os.WriteFile(*output, append(data, '\n'), 0o600); err != nil {
		log.Fatal(err)
	}
}
