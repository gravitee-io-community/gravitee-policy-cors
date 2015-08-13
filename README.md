# Cors Gravitee Policy

[![Build Status](http://build.gravitee.io/jenkins/buildStatus/icon?job=gravitee-policy-cors)](http://build.gravitee.io/jenkins/job/gravitee-policy-cors/)

CORS management Policy which lets you to add/set/remove CORS HTTP headers from and to the API response.

This implementation only reacts on the ``OPTIONS`` preflighted HTTP header by adding/setting/removing configured CORS headers from and to the API response. Thus, this implementation does not acts as a CORS negociation checker nor a full CORS dealer that could add CORS negociation to an API that does not support it.

This implementation is based on the W3C recommendation from the REC-cors-20140116. See http://www.w3.org/TR/2014/REC-cors-20140116/ for more details.