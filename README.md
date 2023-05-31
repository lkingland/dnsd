# dnsd #

[![GoDoc](https://godoc.org/github.com/lkingland/dnsd?status.svg)](https://godoc.org/github.com/lkingland/dnsd)

Dnsd is a Go package that implements a very simple library for use as 
a Cloudflare DNS record update daemon. 

When unable to obtain a static IP address, this libray can be used to implement
a system which will update DNS records when the publicly-routable IP address
changes.

!!!! Warning !!!!

This is a work in progress.

This is pre-1.0.  Please expect bugs and for the API to change.  Use
at your own risk, and please open issues with questions or bugs.

## Usage

Create a populatad `dnsd.Syncer` struct for each domain to keep synchronized
and call `Start()`


