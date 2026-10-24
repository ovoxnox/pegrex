// go_client.go -- minimal pegrex service client (JSON-lines over stdio).
// Run the service: `python service.py`; speak one JSON object per line.
// This is the entire integration surface for Go consumers.

package main

import (
    "bufio"
    "encoding/json"
    "fmt"
    "os/exec"
)

func main() {
    cmd := exec.Command("python", "service.py")
    stdin, _ := cmd.StdinPipe()
    stdout, _ := cmd.StdoutPipe()
    cmd.Start()

    req := map[string]interface{}{
        "method": "parse",
        "params": map[string]interface{}{
            "language": "python",
            "source":   "def f(n):\n    return n",
        },
    }
    b, _ := json.Marshal(req)
    fmt.Fprintln(stdin, string(b))

    scan := bufio.NewScanner(stdout)
    scan.Scan()
    raw := scan.Bytes()
    fmt.Printf("client received: %s\n", raw)
    var resp map[string]interface{}
    if err := json.Unmarshal(raw, &resp); err != nil {
        fmt.Println("unmarshal error:", err)
        return
    }
    if ast, ok := resp["ast"].(map[string]interface{}); ok {
        fmt.Println("ast tag:", ast["tag"])
    } else {
        fmt.Println("no ast in response; keys:", resp)
    }
}
