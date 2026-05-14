package main

import (
	"log"
	"net/http"
	"os"

	sdkmcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/1MansiS/qsafe/internal/ragclient"
	qmcp "github.com/1MansiS/qsafe/mcp"
)

func main() {
	ragURL := os.Getenv("RAG_URL")
	if ragURL == "" {
		ragURL = "http://localhost:8000"
	}

	rag := ragclient.New(ragURL)
	server := qmcp.NewServer(rag)

	handler := sdkmcp.NewStreamableHTTPHandler(func(r *http.Request) *sdkmcp.Server {
		return server
	}, nil)

	addr := ":8080"
	log.Printf("qsafe MCP server listening on %s", addr)
	log.Printf("RAG service: %s", ragURL)

	if err := http.ListenAndServe(addr, handler); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
