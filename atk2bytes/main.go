package main

import (
    "fmt"
    "bufio"
    "os"
)

func main() {
    var cmd string
    scanner := bufio.NewScanner(os.Stdin)

    for scanner.Scan() {
        cmd = scanner.Text()
        atk, err := NewAttack(cmd, 0)
        if err != nil {
            fmt.Printf("ERR|%s\x1b[39;49m\n", err)
            continue
        }

        out, err := atk.Build()
        if err != nil {
            fmt.Printf("ERR|%s\x1b[39;49m\n", err)
            continue
        }

        fmt.Printf("%s", out)
    }
}
