package parser

import (
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation/cftypes"
)

func ResolveReference(property *Property) (resolved *Property, success bool) {
	if !property.isFunction() {
		return property, true
	}

	refProp := property.AsMap()["Ref"]
	if refProp.IsNotString() {
		return property, false
	}
	refValue := refProp.AsString()

	if pseudo, ok := pseudoParameters[refValue]; ok {
		return property.deriveResolved(pseudo.t, pseudo.val), true
	}

	if property.ctx == nil {
		return property, false
	}

	param, ok := property.ctx.Parameters[refValue]
	if ok {
		resolvedType := param.Type()
		switch param.Default().(type) {
		case bool:
			resolvedType = cftypes.Bool
		case string:
			resolvedType = cftypes.String
		case int:
			resolvedType = cftypes.Int
		}

		resolved = property.deriveResolved(resolvedType, param.Default())
		return resolved, true
	}

	res, ok := property.ctx.Resources[refValue]
	if ok {
		resolved = property.deriveResolved(cftypes.String, res.ID())
	}

	return resolved, true
}
