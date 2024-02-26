package main

import (
	"context"
	"fmt"

	"github.com/ethereum/go-ethereum/graphql"
)

func main() {
	ctx := context.Background()
	l := graphql.Log{}
	d := l.Index(ctx)
	fmt.Println(d)
}
