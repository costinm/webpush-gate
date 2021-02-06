title: Openspeedtest and Istio
tags: istio perf 
--- 

# Openspeedtest

- https://github.com/librespeed/speedtest-go


```
docker pull openspeedtest/latest:speedtest 2) docker run --restart=unless-stopped --name=openspeedtest -d -p 80:8080 openspeedtest/latest:speedtest
```

Supports FreeNAS, unraidNAS
