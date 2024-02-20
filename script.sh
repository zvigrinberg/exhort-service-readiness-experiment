
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



      
      


