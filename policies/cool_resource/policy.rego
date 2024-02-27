package example

import future.keywords.in
import future.keywords.if

analyze[risk_path] {
	some index, perm in input.sub_resource_permissions
    some i, pol in perm.acl
    pol ==  "RiskyWrite"
    perm.encrypted == false
    risk_path := sprintf("sub_resource_permissions.%v.encrypted", [index]) 
}

analyze[risk_path] {
	some index, perm in input.sub_resource_permissions
    some i, pol in perm.acl
    pol ==  "RiskyWrite"
    not perm.encrypted
    risk_path := sprintf("sub_resource_permissions.%v", [index]) 
}






