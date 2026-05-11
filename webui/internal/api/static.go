package api

import (
	"embed"
	"io/fs"
	"net/http"
)

//go:embed all:dist
var staticFiles embed.FS

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFiles, "dist")
	if err != nil {
		panic(err)
	}
	fsHandler := http.FileServer(http.FS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// For SPA: fall back to index.html for unknown paths
		_, err := fs.Stat(sub, r.URL.Path[1:])
		if err != nil {
			r2 := *r
			r2.URL.Path = "/"
			fsHandler.ServeHTTP(w, &r2)
			return
		}
		fsHandler.ServeHTTP(w, r)
	})
}
