# K8S Proxy


```shell script
 Core API:
  /api/v1/namespaces/[namespace]/[resource]/[resourceName]/
 ApiGroup:
   
   /apis/[apiGroup]/[apiVersion]/namespaces/[namespace]/[resource]/[resourceName]/

Example:

 /api/v1/namespaces/default/pods/nginx-5dc7fbd98-hvv6s/log

```

Special extra for pods:
    /proxy, /exec, /attach, /logs

Query:
    follow=true 
    
- logs - regular get response, follow leaves open
- exec/attach: Websocket with multiplexed streams, each frame is:

    - StreamNr (1B)
    - DATA 
    
- proxy: 

    - Stream (1B)
    - Port (2B)
    - Data

- Query: watch=true
  Returns Watch objects, with data inside.

https://www.oreilly.com/library/view/managing-kubernetes/9781492033905/ch04.html



# RBAC

apiGroups
resources - also allows subresource
verbs 
resourceNames

For things not following the pattern, only in ClusterRole:

nonResourceURLs - with * at the end
