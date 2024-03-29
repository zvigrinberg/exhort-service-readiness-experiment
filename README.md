# exhort-service-readiness-experiment

## Goal 
To show that in case [exhort](https://github.com/RHEcosystemAppEng/exhort) deployment is deployed with more than 1 replica, then it's possible that one of the pods
has bad connectivity to the internet ( due to networking issues on the node that it's deployed on), and in such case, without fine-grained readiness check, that takes into
account the status of all providers of exhort, the service will forward traffic to all pods, including ones that has internet problems.

## How to Simulate a faulty pod/node
Since exhort image is very minimal, without network tools, and without package manager to install such tools ( for security and pull image performance reasons) , we won't manipulate the network interfaces of the application container inside the pod, in order to simulate broken internet connectivity.
it's also quite complicated, as in such case you need to cherry-pick the right network interface, and disable/turn it off,  but you need to make sure that this network interface is the one that bridge the pod' container to the default/internet gateway address, and not network interface responsible for internal pod to pod and service to pod networking.
Instead of this ( as not possible with exhort image and quite complicated and not worthawhile even if it was possible), we will use a different a approach, described in the following section.

## Procedure - 2 Ways to Simulate a pod failure

### Using Overriding of Snyk API Address with wrong address via environment variable 
1. we will create a new project exhort-test
2. we will create the exhort secret from the exhort namespace
```shell
 oc get secret exhort-secret --namespace exhort -o yaml | sed 's/namespace: exhort/namespace: exhort-test/g' | oc apply -f -
```
3. We will create an exhort deployment of 1 or 2 replicas of exhort.
```shell
oc apply -f exhort.yaml
```
4. We created also a service pointing to the deployment' pods in the above yaml file
5. Then we will create a debug pod yaml out of one of the replicas pods:
```shell
oc debug pod/exhort-pod-name -o yaml > pod-debug.yaml
```
6. In pod-debug.yaml file, we'll remove containers[0]. Command entrypoint override , and will add to the pod definiton the following label:
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
9. The service should add now this pod IP as an endpoint that it load-balance traffic to, verify it
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
13. Tried 2 more times and got same response as above - 404 from snyk , fourth time gave
Response Output:
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
14. To tear down and clean up resources , Delete Project
```shell
oc delete project exhort-test
```

### Simulating By Blocking External access from 1 pod to real snyk address using firewall

1. we will create a new project exhort-test
2. we will create the exhort secret from the exhort namespace
```shell
 oc get secret exhort-secret --namespace exhort -o yaml | sed 's/namespace: exhort/namespace: exhort-test/g' | oc apply -f -
```
3. We will create an exhort deployment of 2 replicas of exhort.
```shell
oc apply -f exhort.yaml
```
4. We created also a service pointing to the deployment' pods in the above yaml file
5. Now get node name of one of the pods (doesn't matter which on of the 2)
```shell
export NODE_NAME=$(oc get pods -l app=exhort | grep -m 1 exhort- | awk ' {print $1}' | xargs -i oc get pod {} -o=jsonpath='{..nodeName}')
```
6. and debug the node:
```shell
oc debug node/$NODE_NAME
## In debug pod, enter the following
chroot /host
```
7. Now inside the debug pod, get the pod name from container runtime
```shell
export POD_ID=$(crictl pods | grep -m 1 -i -E 'exhort-[0-9a-f]' | awk '{print $1}')
```
8. Now get the application container id inside the pod
```shell
export CONTAINER_ID=$(crictl ps | grep $POD_ID | awk '{print $1}')
```

9. Now using container id, get its linux network namespace
```shell
export NETWORK_NS=$(crictl inspect $CONTAINER_ID | jq .info.runtimeSpec.linux.namespaces | grep network -A 2  | grep path | awk -F "netns/" '{print $2}' | tr '"' ' ')
```

10. Get IP Address of Snyk API Service
```shell
export SNYK_IP=$(dig +short api.snyk.io)
```

11. Now block external access to snyk api IP in the container network namespace, to make snyk api site not available for pod, we will use iproute2' ip utility together with iptables firewall directly on the linux network namespace of the application container inside the pod:
```shell
ip netns exec $NETWORK_NS iptables -A OUTPUT -p tcp -d $SNYK_IP  -j DROP
```

12. In Another terminal session ( do not exit the debug pod of the node) , spin up a new rest-api-client pod, that will invoke the service:
```shell
 oc run -it rest-api-client --image=ubi9/ubi:latest -- bash
```
13. In anotehr terminal session, copy sbom.json file in this repo, into the client pod
```shell
oc cp sbom-example.json rest-api-client:/tmp/sbom.json
```

14. Now invoke A Couple of times the exhort analysis endpoint, it will give you alternately a valid response and an erroneous response from the pod that we manipulated its container' network namespace using iptables firewall
```shell
curl -i -X POST http://exhort:8080/api/v4/analysis -H 'Content-Type:application/vnd.cyclonedx+json' -H 'Accept:application/json' -d  @/tmp/sbom.json
```
Actual Output ( it will give you both of the payloads alternately):
```json
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
        "code" : 500,
        "message" : "timeout timed out"
      }
    }
  }
```

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
Note: This situation, that non productive/non informational json responses containing merely errors, having their way to clients a lot of time without fine-grained health check, is not desired situation, being said in an understatement.

### Introducing new readiness probe in exhort 
- Test it and make it work according to requirements.
- Compare new exhort (let's call it exhort-healthier ) with regular exhort

**_New Readiness health check synopsis implemented in exhort:_**

```java
@Readiness
@ApplicationScoped
public class ExternalServiceReadinessProbe implements HealthCheck {
    public static final String OSV_NVD_MINIMAL_REQUEST_BODY = "{\"purls\": [] }";
    public static final String SNYK_MINIMAL_REQUEST_BODY =
            "{\"depGraph\":{\"schemaVersion\":\"1.2.0\",\"pkgManager\":{\"name\":\"maven\"},\"pkgs\":[{\"id\":\"com.redhat.exhort:default-app@0.0.1\",\"info\":{\"name\":\"com.redhat.exhort:default-app\",\"version\":\"0.0.1\"}},{\"id\":\"com.redhat.exhort:default-dep@0.0.1\",\"info\":{\"name\":\"com.redhat.exhort:default-dep\",\"version\":\"0.0.1\"}}],\"graph\":{\"rootNodeId\":\"com.redhat.exhort:default-app@0.0.1\",\"nodes\":[{\"nodeId\":\"com.redhat.exhort:default-app@0.0.1\",\"pkgId\":\"com.redhat.exhort:default-app@0.0.1\",\"deps\":[{\"nodeId\":\"com.redhat.exhort:default-dep@0.0.1\"}]},{\"nodeId\":\"com.redhat.exhort:default-dep@0.0.1\",\"pkgId\":\"com.redhat.exhort:default-dep@0.0.1\",\"deps\":[]}]}}}";
    public static final String OSS_INDEX_MINIMAL_REQUEST_BODY = "{ \"coordinates\": [] }";
    public static final String TRUSTED_CONTENT_MINIMAL_REQUEST_BODY = "{ \"purls\": [] }";

    @Inject
    @Named("snyk")
    private RestClient snykClient;

    @Inject
    @Named("osvNvd")
    private RestClient osvNvdClient;

    @Inject
    @Named("ossIndex")
    private RestClient ossIndexClient;

    @Inject
    @Named("trustedContent")
    private RestClient trustedContentClient;

    @ConfigProperty(name = "api.snyk.token")
    private String snykToken;

    @Override
    public HealthCheckResponse call() {
        HealthCheckResponseBuilder responseBuilder =
                HealthCheckResponse.named("External Services Checkup");
        Map<String, String> snyk =
                getStatusFromExternalService(
                        snykClient
                                .request()
                                .header(Constants.AUTHORIZATION_HEADER, String.format("token %s", snykToken)),
                        SNYK_MINIMAL_REQUEST_BODY);
        Map<String, String> ossIndex =
                getStatusFromExternalService(ossIndexClient.request(), OSS_INDEX_MINIMAL_REQUEST_BODY);
        Map<String, String> osvNvd =
                getStatusFromExternalService(osvNvdClient.request(), OSV_NVD_MINIMAL_REQUEST_BODY);
        Map<String, String> trustedContent =
                getStatusFromExternalService(
                        trustedContentClient.request(), TRUSTED_CONTENT_MINIMAL_REQUEST_BODY);
        responseBuilder =
                responseBuilder
                        .withData("Snyk Provider Status", (String) snyk.get("httpStatus"))
                        .withData("Snyk Provider Description", (String) snyk.get("Description"))
                        .withData("osvNvd Provider Status", (String) osvNvd.get("httpStatus"))
                        .withData("osvNvd Provider Description", (String) osvNvd.get("Description"))
                        .withData("trusted-Content Provider", (String) trustedContent.get("httpStatus"))
                        .withData("trusted-Content Description", (String) trustedContent.get("Description"));

        // if enabled
        responseBuilder =
                responseBuilder
                        .withData("oss-index provider Status", (String) ossIndex.get("httpStatus"))
                        .withData("oss-index provider Description", (String) ossIndex.get("Description"));

        if (serviceReturnNoError(snyk)
                || serviceReturnNoError(ossIndex)
                // TODO - instead of considering 401 && 403 as success for oss-index provider, add
                // properties of ossIndex username + token/password to application.properties, as default
                // credentials ( as we have default token in snyk)
                // , and remove the following two lines .
                || getStatsCodeFromExternalService(ossIndex) == 401
                || getStatsCodeFromExternalService(ossIndex) == 403
                || serviceReturnNoError(osvNvd))
        // as long as trusted Content is not a self-contained provider, it shouldn't affect the
        // readiness probe result.
        //        || serviceReturnNoError(trustedContent))
        {
            return responseBuilder.up().build();
        } else {
            return responseBuilder.down().build();
        }
    }
}
```

**_Or using Camel routes to leverage exhort existing camel routes:_**

```java
public class ProviderHealthCheck extends AbstractHealthCheck {

  private static final List<String> allProvidersHealthChecks =
      List.of("direct:snykHealthCheck", "direct:osvNvdHealthCheck", "direct:ossIndexHealthCheck");

  public ProviderHealthCheck() {
    super("External Providers Readiness Check");
  }

  @Override
  protected void doCall(HealthCheckResultBuilder builder, Map<String, Object> options) {
    var response =
        getCamelContext()
            .createProducerTemplate()
            .send(
                "direct:exhortHealthCheck",
                ExchangeBuilder.anExchange(getCamelContext())
                    .withHeader(
                        Constants.HEALTH_CHECKS_LIST_HEADER_NAME, this.allProvidersHealthChecks)
                    .build());

    List<Map<String, ProviderStatus>> httpResponseBodiesAndStatuses =
        (List<Map<String, ProviderStatus>>) response.getMessage().getBody();
    Map<String, Object> providers =
        httpResponseBodiesAndStatuses.stream()
            .map(Map::entrySet)
            .flatMap(Collection::stream)
            .collect(
                Collectors.toMap(
                    entry -> entry.getKey(), entry -> formatProviderStatus(entry), (a, b) -> a));
    builder.details(providers);

    if (httpResponseBodiesAndStatuses.stream()
        .map(Map::values)
        .flatMap(Collection::stream)
        .filter(providerStatus -> Objects.nonNull(providerStatus.getCode()))
        .anyMatch(providerDetails -> providerDetails.getCode() < 400 && providerDetails.getOk())) {
      builder.up();

    } else {
      builder.down();
    }
  }

  private static String formatProviderStatus(Map.Entry<String, ProviderStatus> entry) {
    ProviderStatus provider = entry.getValue();
    if (Objects.nonNull(provider.getCode())) {
      return String.format(
          "providerName=%s, isEnabled=%s, statusCode=%s, message=%s",
          provider.getName(), provider.getOk(), provider.getCode(), provider.getMessage());
    } else {
      return String.format(
          "providerName=%s, isEnabled=%s, message=%s",
          provider.getName(), provider.getOk(), provider.getMessage());
    }
  }

  @Override
  public boolean isLiveness() {
    return false;
  }
}
@ApplicationScoped
public class ExhortIntegration extends EndpointRouteBuilder {
@Override
  public void configure() {
//.............
//.............
      from(direct("exhortHealthCheck"))
	.routeId("exhortHealthCheck")
	.setProperty(PROVIDERS_PARAM, method(vulnerabilityProvider, "getEnabled"))
	.recipientList(header(Constants.HEALTH_CHECKS_LIST_HEADER_NAME))
	 .aggregationStrategy(new ProvidersBodyPlusResponseCodeAggregationStrategy());
  }
}


```


15. Now we will Built exhort with this new readiness probe as a native executable, and built an image
16. Deploy exhort-healthier deployment +  its exhort-healthier service to same namespace/project
```shell
oc apply -f exhort-healthier.yaml
```
17. Now get node name of one of the pods (doesn't matter which on of the 2)
```shell
export NODE_NAME=$(oc get pods -l app=exhort-healthier | grep -m 1 exhort- | awk ' {print $1}' | xargs -i oc get pod {} -o=jsonpath='{..nodeName}')
```
18. and debug the node:
```shell
oc debug node/$NODE_NAME
```
19. Now inside the debug pod of node, get the pod name from container runtime
```shell
export POD_ID=$(crictl pods | grep -m 1 -i -E 'exhort-healthier-[0-9a-f]' | awk '{print $1}')
```
20. Now get the application container id inside the pod
```shell
export CONTAINER_ID=$(crictl ps | grep $POD_ID | awk '{print $1}')
```
21. Now using container id, get its linux network namespace
```shell
export NETWORK_NS=$(crictl inspect $CONTAINER_ID | jq .info.runtimeSpec.linux.namespaces | grep network -A 2  | grep path | awk -F "netns/" '{print $2}' | tr '"' ' ')
```
22. Get IP Address of Snyk API Service
```shell
export SNYK_IP=$(dig +short api.snyk.io)
```

23. Now block external access to snyk api IP in the container network namespace, to make snyk api site not available for pod, we will use iptables firewall directly on the linux network namespace of the application container inside the pod:
```shell
ip netns exec $NETWORK_NS iptables -A OUTPUT -p tcp -d $SNYK_IP  -j DROP
```
24. In Another terminal session ( do not exit the debug pod of the node) , copy script to rest-api-client pod in order to test both deployments, exhort, and exhort-healthier, in order to see differences between them
```shell
oc cp script.sh rest-api-client:/tmp/script.sh
```
25. install jq (json query util) in order to parse json responses, and then after Invoke the script inside the pod  to test both deployments through invoking 40 request via their services ( 20 requests in each service )
Script that is going to be invoked inside the pod
```shell

declare -i FAIL_COUNT_EXHORT=0
declare -i FAIL_COUNT_EXHORT_HEALTHIER=0
for i in {1..20}
  do
     echo attempt $i for invoking exhort  
     export RESULT_EXHORT=$(curl -q -X POST http://exhort:8080/api/v4/analysis -H 'Content-Type:application/vnd.cyclonedx+json' -H 'Accept:application/json' -d  @/tmp/sbom.json |  jq .providers.snyk.status.code)
     echo attempt $i for invoking exhort-healthier
     export RESULT_EXHORT_HEALTHIER=$(curl -q -X POST http://exhort-healthier:8080/api/v4/analysis -H 'Content-Type:application/vnd.cyclonedx+json' -H 'Accept:application/json' -d  @/tmp/sbom.json |  jq .providers.snyk.status.code)
     if [[ "$RESULT_EXHORT" == "500" ]]
     then
	     ((FAIL_COUNT_EXHORT++))
     fi
     if [[ "$RESULT_EXHORT_HEALTHIER" == "500" ]]
     then
             ((FAIL_COUNT_EXHORT_HEALTHIER++))
     fi
     
done

echo "Number of failures in exhort service= $FAIL_COUNT_EXHORT"
echo "Number of failures in exhort-healthier service= $FAIL_COUNT_EXHORT_HEALTHIER"
```

Running Script in pod:
```shell
 oc exec rest-api-client -- bash -c "yum install -y jq ; /tmp/script.sh"
```
Final Output:
```shell
Number of failures in exhort service= 10
Number of failures in exhort-healthier service= 0
```

19. To tear down and clean up resources , Delete Project
```shell
oc delete project exhort-test
```
