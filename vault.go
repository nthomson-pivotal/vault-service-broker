package main

import (
	"html/template"
	"io"
)

const (
	ServicePolicyTemplateWithoutNames string = `
path "cf/{{ .ServiceInstanceGUID }}" {
  capabilities = ["list"]
}

path "cf/{{ .ServiceInstanceGUID }}/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}

path "cf/{{ .SpaceGUID }}" {
  capabilities = ["list"]
}

path "cf/{{ .SpaceGUID }}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

path "cf/{{ .OrganizationGUID }}" {
  capabilities = ["list"]
}

path "cf/{{ .OrganizationGUID }}/*" {
  capabilities = ["read", "list"]
}
`

	// ServicePolicyTemplateWithNames is identical to the above, but adds paths for name-ID mount path combos
	ServicePolicyTemplateWithNames string = `
path "cf/{{ .ServiceInstanceName }}-{{ .ServiceInstanceGUID }}" {
  capabilities = ["list"]
}
path "cf/{{ .ServiceInstanceGUID }}" {
  capabilities = ["list"]
}
path "cf/{{ .ServiceInstanceName }}-{{ .ServiceInstanceGUID }}/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}
path "cf/{{ .ServiceInstanceGUID }}/*" {
	capabilities = ["create", "read", "update", "delete", "list"]
}
path "cf/{{ .SpaceName }}-{{ .SpaceGUID }}" {
  capabilities = ["list"]
}
path "cf/{{ .SpaceGUID }}" {
  capabilities = ["list"]
}
path "cf/{{ .SpaceName }}-{{ .SpaceGUID }}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "cf/{{ .SpaceGUID }}/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
path "cf/{{ .OrganizationName }}-{{ .OrganizationGUID }}" {
  capabilities = ["list"]
}
path "cf/{{ .OrganizationGUID }}" {
  capabilities = ["list"]
}
	// SpaceID is the unique ID of the space.
	SpaceID string
path "cf/{{ .OrganizationName }}-{{ .OrganizationGUID }}/*" {
  capabilities = ["read", "list"]
}
	// OrgID is the unique ID of the space.
	OrgID string
path "cf/{{ .OrganizationGUID }}/*" {
  capabilities = ["read", "list"]
}
`
)

// GeneratePolicy takes an io.Writer object and template input and renders the
// resulting template into the writer.
func GeneratePolicy(w io.Writer, i *instanceInfo) error {
	toParse := ServicePolicyTemplateWithNames
	if i.OrganizationName == "" || i.SpaceName == "" || i.ServiceInstanceName == "" {
		toParse = ServicePolicyTemplateWithoutNames
	}
	tmpl, err := template.New("service").Parse(toParse)
	if err != nil {
		return err
	}
	return tmpl.Execute(w, i)
}
