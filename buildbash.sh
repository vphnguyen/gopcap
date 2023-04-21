#!/usr/bin/bash
archs=(amd64 arm arm64  386) 

for arch in ${archs[@]}
do
	env GOOS=linux GOARCH=${arch} go build -o reqcounter_${arch}
done
