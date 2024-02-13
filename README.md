# exhort-service-readiness-experiment

## Goal 
To show that in case [exhort] deployment is deployed with more than 1 replica, then it's possible that one of the pods
has bad connectivity to the internet ( due to networking issues on the node that it's deployed on), and in such case, without fine grained readiness check, that takes into
account the status of all providers of exhort, the service will forward traffic to all pods, including ones that has internet problems.

## How to Simulate a faulty pod/node
Since exhort image is very minimal, without network tools, we won't tweak the network interfaces of the application container inside the pod, in order to simulate broken internet connectivity.
it's also quite complicated, as in such case you need to cherry-pick the right network interface, and disable/turn it off,  but you need to make sure that this network interface is the one that bridge the pod' container to the default/internet gateway address, and not network interface responsible for internal pod to pod and service to pod networking.
Instead of this ( as not possible with exhort image and quite complicated and not worthawhile even if it was possible), we will use a different a approach, describe in the following section.

## Procedure
1. we will create a new project exhort-test
2. we will create the exhort secret from the exhort namespace
```shell
 oc get secret exhort-secret --namespace exhort -o yaml | sed 's/namespace: exhort/namespace: exhort-test/g' | oc apply -f -
```
3. We will create an exhort deployment of 1 or 2 replicas of exhort.
```shell
oc apply -f exhort.yaml
```
4. We will create a service pointing to the deployment' pods
5. Then we will create a debug pod yaml out of one of the replicas pods:
```shell
oc debug pod/exhort-pod-name -o yaml > pod-debug.yaml
```
6. in pod-debug.yaml file, we'll remove containers[0].command entrypoint override , and will add to the pod definiton the following label:
```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
  generateName: exhort-6f58d7577-
  name: exhort-6f58d7577-mwxd4-debug
  namespace: exhort-test
  labels:
    app: exhort

```

7. Again, in pod-debug.yaml, let's override the application.properties' api.snyk.host valid snyk endpoint with non exists one ( this action actually simulates the error from provider that we need)
```yaml
apiVersion: v1
kind: Pod
metadata:
  annotations:
  generateName: exhort-6f58d7577-
  name: exhort-6f58d7577-mwxd4-debug
  namespace: exhort-test
  labels:
    app: exhort
spec:
  containers:
  - env:
    - name: API_SNYK_HOST
      value: https://app.snyk.io/api/v5
```   
8. Deploy the pod to cluster in the same cluster
```shell
oc apply -f pod-debug.yaml
```   
9. The service should add now this pod IP as an endpoint that it loadbalance traffic to, verify it
```shell
oc get pod -o wide
oc describe endpoints
````
10. Now spin up a new rest-api-client pod, that will invoke the service:
```shell
 oc run -it rest-api-client --image=ubi9/ubi:latest -- bash
```
11. In anotehr terminal session, copy sbom.json file in this repo, into the client pod
```shell
oc cp sbom-example.json rest-api-client:/tmp/sbom.json
```
12. Now invoke post request from client pod , 1st time
```shell
curl -i -X POST http://exhort:8080/api/v4/analysis -H 'Content-Type:application/vnd.cyclonedx+json' -H 'Accept:application/json' -d  @/tmp/sbom.json 
```
Response Output:
```json
HTTP/1.1 200 OK
ex-request-id: a4a5f1923f3207f6ff0306b787c3f5fcd27dad671837f24f3e1851c8fed30249
User-Agent: curl/7.76.1
transfer-encoding: chunked
Content-Type: application/json

{
  "scanned" : {
    "total" : 145,
    "direct" : 9,
    "transitive" : 136
  },
  "providers" : {
    "trusted-content" : {
      "status" : {
        "ok" : true,
        "name" : "trusted-content",
        "code" : 200,
        "message" : "OK"
      }
    },
    "osv-nvd" : {
      "status" : {
        "ok" : false,
        "name" : "osv-nvd",
        "code" : 500,
        "message" : "onguard: System error"
      }
    },
    "snyk" : {
      "status" : {
        "ok" : false,
        "name" : "snyk",
        "code" : 404,
        "message" : "Not Found: {\"code\":404,\"message\":\"bad API request, please contact support@snyk.io for assistance\",\"error\":\"unsupported url\"}"
      }
    }
  }
}
```
11. Tried 2 more times and got same response as above - 404 from snyk , fourth time gave
Response Output    
```json
{
  "scanned" : {
    "total" : 138,
    "direct" : 9,
    "transitive" : 129
  },
  "providers" : {
    "snyk" : {
      "status" : {
        "ok" : true,
        "name" : "snyk",
        "code" : 200,
        "message" : "OK"
      },
      "sources" : {
        "snyk" : {
          "summary" : {
            "direct" : 8,
            "transitive" : 3,
            "total" : 11,
            "dependencies" : 3,
            "critical" : 0,
            "high" : 4,
            "medium" : 6,
            "low" : 1,
            "remediations" : 0,
            "recommendations" : 0
          },
          "dependencies" : [ {
            "ref" : "pkg:npm/axios@0.19.2",
            "issues" : [ {
              "id" : "SNYK-JS-AXIOS-1579269",
              "title" : "Regular Expression Denial of Service (ReDoS)",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "Low",
                "privilegesRequired" : "None",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "None",
                "integrityImpact" : "None",
                "availabilityImpact" : "High",
                "exploitCodeMaturity" : "Proof of concept code",
                "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H/E:P"
              },
              "cvssScore" : 7.5,
              "severity" : "HIGH",
              "cves" : [ "CVE-2021-3749" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "0.21.3" ]
              }
            }, {
              "id" : "SNYK-PRIVATE-VULNERABILITY",
              "title" : "Sign up for a Snyk account to learn aboutn the vulnerabilities found",
              "source" : "snyk",
              "cvssScore" : 7.5,
              "severity" : "HIGH",
              "unique" : true,
              "remediation" : {
                "fixedIn" : [ "1.6.4" ]
              }
            }, {
              "id" : "SNYK-JS-AXIOS-6032459",
              "title" : "Cross-site Request Forgery (CSRF)",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "Low",
                "privilegesRequired" : "None",
                "userInteraction" : "Required",
                "scope" : "Unchanged",
                "confidentialityImpact" : "High",
                "integrityImpact" : "Low",
                "availabilityImpact" : "None",
                "exploitCodeMaturity" : "Proof of concept code",
                "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N/E:P"
              },
              "cvssScore" : 7.1,
              "severity" : "HIGH",
              "cves" : [ "CVE-2023-45857" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "1.6.0" ]
              }
            }, {
              "id" : "SNYK-JS-AXIOS-1038255",
              "title" : "Server-Side Request Forgery (SSRF)",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "High",
                "privilegesRequired" : "None",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "High",
                "integrityImpact" : "None",
                "availabilityImpact" : "None",
                "exploitCodeMaturity" : "Proof of concept code",
                "cvss" : "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N/E:P"
              },
              "cvssScore" : 5.9,
              "severity" : "MEDIUM",
              "cves" : [ "CVE-2020-28168" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "0.21.1" ]
              }
            }, {
              "id" : "SNYK-PRIVATE-VULNERABILITY",
              "title" : "Sign up for a Snyk account to learn aboutn the vulnerabilities found",
              "source" : "snyk",
              "cvssScore" : 5.3,
              "severity" : "MEDIUM",
              "unique" : true,
              "remediation" : {
                "fixedIn" : [ "1.6.3" ]
              }
            } ],
            "transitive" : [ {
              "ref" : "pkg:npm/follow-redirects@1.5.10",
              "issues" : [ {
                "id" : "SNYK-JS-FOLLOWREDIRECTS-6141137",
                "title" : "Improper Input Validation",
                "source" : "snyk",
                "cvss" : {
                  "attackVector" : "Network",
                  "attackComplexity" : "Low",
                  "privilegesRequired" : "None",
                  "userInteraction" : "None",
                  "scope" : "Unchanged",
                  "confidentialityImpact" : "Low",
                  "integrityImpact" : "Low",
                  "availabilityImpact" : "Low",
                  "exploitCodeMaturity" : "Proof of concept code",
                  "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P"
                },
                "cvssScore" : 7.3,
                "severity" : "HIGH",
                "cves" : [ "CVE-2023-26159" ],
                "unique" : false,
                "remediation" : {
                  "fixedIn" : [ "1.15.4" ]
                }
              }, {
                "id" : "SNYK-JS-FOLLOWREDIRECTS-2332181",
                "title" : "Information Exposure",
                "source" : "snyk",
                "cvss" : {
                  "attackVector" : "Network",
                  "attackComplexity" : "High",
                  "privilegesRequired" : "None",
                  "userInteraction" : "Required",
                  "scope" : "Unchanged",
                  "confidentialityImpact" : "High",
                  "integrityImpact" : "None",
                  "availabilityImpact" : "None",
                  "exploitCodeMaturity" : "Proof of concept code",
                  "cvss" : "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N/E:P"
                },
                "cvssScore" : 5.3,
                "severity" : "MEDIUM",
                "cves" : [ "CVE-2022-0155" ],
                "unique" : false,
                "remediation" : {
                  "fixedIn" : [ "1.14.7" ]
                }
              }, {
                "id" : "SNYK-JS-FOLLOWREDIRECTS-2396346",
                "title" : "Information Exposure",
                "source" : "snyk",
                "cvss" : {
                  "attackVector" : "Adjacent Network",
                  "attackComplexity" : "High",
                  "privilegesRequired" : "Low",
                  "userInteraction" : "None",
                  "scope" : "Unchanged",
                  "confidentialityImpact" : "Low",
                  "integrityImpact" : "None",
                  "availabilityImpact" : "None",
                  "cvss" : "CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"
                },
                "cvssScore" : 2.6,
                "severity" : "LOW",
                "cves" : [ "CVE-2022-0536" ],
                "unique" : false,
                "remediation" : {
                  "fixedIn" : [ "1.14.8" ]
                }
              } ],
              "highestVulnerability" : {
                "id" : "SNYK-JS-FOLLOWREDIRECTS-6141137",
                "title" : "Improper Input Validation",
                "source" : "snyk",
                "cvss" : {
                  "attackVector" : "Network",
                  "attackComplexity" : "Low",
                  "privilegesRequired" : "None",
                  "userInteraction" : "None",
                  "scope" : "Unchanged",
                  "confidentialityImpact" : "Low",
                  "integrityImpact" : "Low",
                  "availabilityImpact" : "Low",
                  "exploitCodeMaturity" : "Proof of concept code",
                  "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P"
                },
                "cvssScore" : 7.3,
                "severity" : "HIGH",
                "cves" : [ "CVE-2023-26159" ],
                "unique" : false,
                "remediation" : {
                  "fixedIn" : [ "1.15.4" ]
                }
              }
            } ],
            "highestVulnerability" : {
              "id" : "SNYK-JS-FOLLOWREDIRECTS-6141137",
              "title" : "Improper Input Validation",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "Low",
                "privilegesRequired" : "None",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "Low",
                "integrityImpact" : "Low",
                "availabilityImpact" : "Low",
                "exploitCodeMaturity" : "Proof of concept code",
                "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L/E:P"
              },
              "cvssScore" : 7.3,
              "severity" : "HIGH",
              "cves" : [ "CVE-2023-26159" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "1.15.4" ]
              }
            }
          }, {
            "ref" : "pkg:npm/jsonwebtoken@8.5.1",
            "issues" : [ {
              "id" : "SNYK-JS-JSONWEBTOKEN-3180026",
              "title" : "Use of a Broken or Risky Cryptographic Algorithm",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "High",
                "privilegesRequired" : "Low",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "High",
                "integrityImpact" : "High",
                "availabilityImpact" : "None",
                "cvss" : "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N"
              },
              "cvssScore" : 6.8,
              "severity" : "MEDIUM",
              "cves" : [ "CVE-2022-23539" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "9.0.0" ]
              }
            }, {
              "id" : "SNYK-JS-JSONWEBTOKEN-3180024",
              "title" : "Improper Restriction of Security Token Assignment",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "Low",
                "privilegesRequired" : "None",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "Low",
                "integrityImpact" : "Low",
                "availabilityImpact" : "None",
                "cvss" : "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"
              },
              "cvssScore" : 6.5,
              "severity" : "MEDIUM",
              "cves" : [ "CVE-2022-23541" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "9.0.0" ]
              }
            }, {
              "id" : "SNYK-JS-JSONWEBTOKEN-3180022",
              "title" : "Improper Authentication",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "High",
                "privilegesRequired" : "Low",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "Low",
                "integrityImpact" : "High",
                "availabilityImpact" : "Low",
                "cvss" : "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L"
              },
              "cvssScore" : 6.4,
              "severity" : "MEDIUM",
              "cves" : [ "CVE-2022-23540" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "9.0.0" ]
              }
            } ],
            "highestVulnerability" : {
              "id" : "SNYK-JS-JSONWEBTOKEN-3180022",
              "title" : "Improper Authentication",
              "source" : "snyk",
              "cvss" : {
                "attackVector" : "Network",
                "attackComplexity" : "High",
                "privilegesRequired" : "Low",
                "userInteraction" : "None",
                "scope" : "Unchanged",
                "confidentialityImpact" : "Low",
                "integrityImpact" : "High",
                "availabilityImpact" : "Low",
                "cvss" : "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L"
              },
              "cvssScore" : 6.4,
              "severity" : "MEDIUM",
              "cves" : [ "CVE-2022-23540" ],
              "unique" : false,
              "remediation" : {
                "fixedIn" : [ "9.0.0" ]
              }
            }
          } ]
        }
      }
    }
  }
}
```
