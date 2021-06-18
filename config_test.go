package acm

import (
	"testing"
	"time"
)

func TestNacosConfig_ListenAsync(t *testing.T) {
	conf := NewAcm(func(c *Acm) {
		c.RoleName = "BlogACMRole"
	})

	conf.ListenAsync("26f1d5e2-b698-49cd-9cd9-f534661c388a", "DEFAULT_GROUP", "test", func(cnf string) {
		t.Log(cnf)
	})

	<-time.After(60 * time.Second)
}
