// Copyright 2019 Simon Pasquier
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/api"
	v1 "github.com/prometheus/client_golang/api/prometheus/v1"
	"github.com/prometheus/prometheus/promql"
)

var (
	help    bool
	promURL string
)

func init() {
	flag.BoolVar(&help, "help", false, "Help message")
	flag.StringVar(&promURL, "url", "", "Prometheus base URL")
}

type ruleLinter struct {
	metrics map[string]bool
	client  api.Client
}

func newRuleLinter(promURL string) (*ruleLinter, error) {
	c, err := api.NewClient(api.Config{Address: promURL})
	if err != nil {
		return nil, err
	}
	return &ruleLinter{
		metrics: make(map[string]bool),
		client:  c,
	}, nil
}

func (r *ruleLinter) getRules() ([]string, error) {
	res, err := v1.NewAPI(r.client).Rules(context.Background())
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get rules")
	}

	var queries []string
	for _, group := range res.Groups {
		for _, rule := range group.Rules {
			switch v := rule.(type) {
			case v1.RecordingRule:
				queries = append(queries, v.Query)
			case v1.AlertingRule:
				queries = append(queries, v.Query)
			}
		}
	}

	return queries, nil
}

func (r *ruleLinter) getMetrics(rule string) ([]string, error) {
	expr, err := promql.ParseExpr(rule)
	if err != nil {
		return nil, err
	}

	metrics := make(map[string]struct{})
	promql.Inspect(expr, func(node promql.Node, _ []promql.Node) error {
		switch n := node.(type) {
		case *promql.VectorSelector:
			if n.Name == "" {
				return nil
			}
			metrics[n.Name] = struct{}{}
		case *promql.MatrixSelector:
			if n.Name == "" {
				return nil
			}
			metrics[n.Name] = struct{}{}
		default:
		}
		return nil
	})

	var ret []string
	for k := range metrics {
		ret = append(ret, k)
	}
	return ret, nil
}

func (r *ruleLinter) metricExists(name string) (bool, error) {
	_, ok := r.metrics[name]
	if !ok {
		lset, _, err := v1.NewAPI(r.client).Series(context.Background(), []string{name}, time.Time{}, time.Now())
		if err != nil {
			return false, errors.Wrapf(err, "failed to get metric %q", name)
		}
		r.metrics[name] = len(lset) > 0
	}
	return r.metrics[name], nil
}

func main() {
	flag.Parse()
	if help {
		fmt.Fprintln(os.Stderr, "Prometheus rules linter")
		flag.PrintDefaults()
		os.Exit(0)
	}

	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
}

func run() error {
	if promURL == "" {
		return errors.New("Missing -url parameter")
	}
	u, err := url.Parse(promURL)
	if err != nil {
		return errors.Wrap(err, "Invalid URL")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.Errorf("Invalid URL scheme: %s", u.Scheme)
	}

	linter, err := newRuleLinter(promURL)
	if err != nil {
		return err
	}
	rules, err := linter.getRules()
	if err != nil {
		return err
	}
	for _, rule := range rules {
		metrics, err := linter.getMetrics(rule)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		for _, metric := range metrics {
			found, err := linter.metricExists(metric)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				continue
			}
			if !found {
				fmt.Fprintf(os.Stderr, "rule %q: metric %q not found!\n", rule, metric)
			}
		}
	}

	return nil
}
