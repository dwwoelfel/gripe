package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/graphql-go/graphql"
	"github.com/graphql-go/graphql/language/ast"
	"github.com/graphql-go/graphql/language/kinds"
	"github.com/graphql-go/handler"
	"github.com/iancoleman/strcase"
	"github.com/jinzhu/inflection"
	"golang.org/x/exp/slices"
)

type key string

const stripeFetchKey key = "stripe-fetch"

// Top-level query fields that produce a single object
var singularRootFields = []string{
	"invoice",
	"charge",
	"dispute",
	"refund",
	"balance_transaction",
	"payout",
	"checkout.session",
	"source",
	"coupon",
	"customer",
	"invoiceitem", // This may be fixed in a newer version of the openapi spec
	"payment_intent",
	"plan",
	"subscription",
	"transfer",
	"subscription_item",
	"sku",
	"order",
	"product",
	"price",
	"setup_intent",
	"payment_method",
	"topup",
	"bitcoin_receiver",
}

// Top-level query fields that require a customer
var customerNestedRootFields = []string{
	"bank_account",
	"card",
}

// Top-level query fields that return a connection
var pluralRootFields = []string{
	"customer",
	"invoice",
	"charge",
	"dispute",
	"refund",
	"balance_transaction",
	"checkout.session",
	"payment_intent",
	"plan",
	"subscription",
	"transfer",
	"product",
	"price",
	"setup_intent",
}

// creates additional connection fields on the underlying field
var childConnections = map[string][]string{
	"charge":   {"dispute", "refund"},
	"customer": {"charge", "invoice", "payment_intent"},
	"plan":     {"subscription"},
}

type extraArg struct {
	fieldName string
	param     string
	typ       *graphql.Scalar
}

var extraArgs = map[string][]extraArg{
	"invoice": {
		extraArg{
			fieldName: "status",
			param:     "status",
		},
		extraArg{
			fieldName: "customer",
			param:     "customer",
		},
	},
	"charge": {
		extraArg{
			fieldName: "customer",
			param:     "customer",
		},
	},
	"refund": {
		extraArg{
			fieldName: "chargeId",
			param:     "charge",
		},
	},
	"checkout.session": {
		extraArg{
			fieldName: "subscriptionId",
			param:     "subscription",
		},
		extraArg{
			fieldName: "paymentIntentId",
			param:     "payment_intent",
		},
	},
	"subscription": {
		extraArg{
			fieldName: "customerId",
			param:     "customer",
		},
		extraArg{
			fieldName: "status",
			param:     "status",
		},
		extraArg{
			fieldName: "planId",
			param:     "plan",
		},
	},
	"product": {
		extraArg{
			fieldName: "url",
			param:     "url",
		},
		extraArg{
			fieldName: "productType",
			param:     "product_type",
		},
		extraArg{
			fieldName: "shippable",
			param:     "shippable",
			typ:       graphql.Boolean,
		},
	},
	"price": {
		extraArg{
			fieldName: "priceType",
			param:     "type",
		},
		extraArg{
			fieldName: "product",
			param:     "product",
		},
		extraArg{
			fieldName: "currency",
			param:     "currency",
		},
		extraArg{
			fieldName: "active",
			param:     "active",
			typ:       graphql.Boolean,
		},
	},
	"setup_intent": {
		extraArg{
			fieldName: "customer",
			param:     "customer",
		},
		extraArg{
			fieldName: "paymentMethod",
			param:     "payment_method",
		},
	},
	"payment_intent": {
		extraArg{
			fieldName: "customer",
			param:     "customer",
		},
	},
}

func makeFieldName(p string) string {
	p = strings.ReplaceAll(p, "invoiceitem", "invoice_item")
	return strcase.ToLowerCamel(p)
}

func makeTypeName(p string) string {
	p = strings.ReplaceAll(p, "invoiceitem", "invoice_item")
	return strcase.ToCamel(p)
}

func parseLiteral(astValue ast.Value) interface{} {
	kind := astValue.GetKind()

	switch kind {
	case kinds.StringValue:
		return astValue.GetValue()
	case kinds.BooleanValue:
		return astValue.GetValue()
	case kinds.IntValue:
		return astValue.GetValue()
	case kinds.FloatValue:
		return astValue.GetValue()
	case kinds.ObjectValue:
		obj := make(JsonMap)
		for _, v := range astValue.GetValue().([]*ast.ObjectField) {
			obj[v.Name.Value] = parseLiteral(v.Value)
		}
		return obj
	case kinds.ListValue:
		list := make([]interface{}, 0)
		for _, v := range astValue.GetValue().([]ast.Value) {
			list = append(list, parseLiteral(v))
		}
		return list
	default:
		return nil
	}
}

var jsonObj = graphql.NewScalar(
	graphql.ScalarConfig{
		Name: "JSON",
		Serialize: func(value interface{}) interface{} {
			return value
		},
		ParseValue: func(value interface{}) interface{} {
			return value
		},
		ParseLiteral: parseLiteral,
	},
)

type PageInfo struct {
	HasNextPage     bool
	HasPreviousPage bool
	StartCursor     string
	EndCursor       string
}

var pageInfo = graphql.NewObject(graphql.ObjectConfig{
	Name:        "PageInfo",
	Description: "Information about pagination in a connection",
	Fields: graphql.Fields{
		"hasNextPage": &graphql.Field{
			Description: "When paginating forwards, are there more items?",
			Type:        graphql.NewNonNull(graphql.Boolean),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				return p.Source.(PageInfo).HasNextPage, nil
			},
		},
		"hasPreviousPage": &graphql.Field{
			Description: "When paginating backwards, are there more items?",
			Type:        graphql.NewNonNull(graphql.Boolean),
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				return p.Source.(PageInfo).HasPreviousPage, nil
			},
		},
		"startCursor": &graphql.Field{
			Description: "When paginating backwards, the cursor to continue.",
			Type:        graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				return p.Source.(PageInfo).StartCursor, nil
			},
		},
		"endCursor": &graphql.Field{
			Description: "When paginating forwards, the cursor to continue.",
			Type:        graphql.String,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				return p.Source.(PageInfo).EndCursor, nil
			},
		},
	},
})

type TypeMap = map[string]graphql.Type
type JsonMap = map[string]interface{}

func refKey(ref string) string {
	components := strings.Split(ref, "/")
	return components[len(components)-1]
}

var emptyParams = make(map[string]string, 0)

type stripeFetch = func(path string, params map[string]string) (JsonMap, error)

func makeStripeFetch(token string) stripeFetch {
	return func(path string, params map[string]string) (JsonMap, error) {
		if token == "" {
			return nil, fmt.Errorf("missing auth, a Stripe token should be provided as the value in X-Stripe-Token header or as a bearer token in the Authorization header.")
		}
		client := http.Client{}
		url, err := url.Parse(`https://api.stripe.com` + path)
		if err != nil {
			return nil, err
		}
		values := url.Query()
		for k, v := range params {

			values.Add(k, v)
		}

		url.RawQuery = values.Encode()

		log.Printf("Fetching from stripe, url=%s", url.String())
		req, err := http.NewRequest("GET", url.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header = http.Header{
			"Stripe-Version": {"2020-03-02"},
			"Content-Type":   {"application/json"},
			"Accept":         {"application/json"},
			"Authorization":  {"Bearer " + token},
		}
		res, err := client.Do(req)
		log.Printf("Got a %d for path=%s", res.StatusCode, path)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		jsonMap := make(JsonMap)
		if err := json.NewDecoder(res.Body).Decode(&jsonMap); err != nil {
			return nil, err
		}
		e := jsonMap["error"]
		if e != nil {
			log.Printf("Error from stripe, path=%s, msg=%s", path, e.(JsonMap)["message"])
			return nil, fmt.Errorf("%s", e.(JsonMap)["message"])
		}
		return jsonMap, nil
	}
}

func typeOfProp(
	loader *openapi3.T,
	typeMap TypeMap,
	schemaName string,
	schema *openapi3.SchemaRef,
	propertyName string,
	prop *openapi3.SchemaRef,
) graphql.Type {
	var baseType graphql.Type

	switch prop.Value.Type {
	case "string":
		baseType = graphql.String
	case "integer":
		baseType = graphql.Int
	case "number":
		baseType = graphql.Float
	case "boolean":
		baseType = graphql.Boolean
	case "array":
		baseType = typeOfProp(loader, typeMap, schemaName, schema, propertyName, prop.Value.Items)
		if baseType != nil {
			switch baseType.(type) {
			case *graphql.NonNull:
				// do nothing
			default:
				// wrap list items in non-null
				baseType = graphql.NewNonNull(baseType)
			}

			baseType = graphql.NewList(baseType)
		}
	case "object":
		if propertyName == "metadata" {
			baseType = jsonObj
		} else if prop.Ref != "" {
			typeName := makeTypeName(refKey(prop.Ref))
			baseType = typeMap[typeName]
		} else {
			typeName := makeTypeName(fmt.Sprintf("%s-%s", schemaName, propertyName))
			typ := genTypeFromSchemaRef(loader, typeMap, typeName, prop)
			if typ != nil {
				typeMap[typeName] = typ
				baseType = typ
			}
		}
	}

	if baseType == nil && prop.Value.AnyOf != nil {

		types := make([]*graphql.Object, 0)
		for _, anyOf := range prop.Value.AnyOf {
			anyOf := anyOf
			if anyOf.Ref != "" {
				typeName := makeTypeName(refKey(anyOf.Ref))
				typ := typeMap[typeName]
				types = append(types, typ.(*graphql.Object))
			}
		}

		if len(types) == 1 {
			baseType = types[0]
		} else {
			typeName := makeTypeName(fmt.Sprintf("%s-%s-union", schemaName, propertyName))
			typ := graphql.NewUnion(graphql.UnionConfig{
				Name:  typeName,
				Types: types,
				ResolveType: func(p graphql.ResolveTypeParams) *graphql.Object {
					/// TODO: Better handling for deleted objects (their "object" will be "customer", but they'll have deleted = true)
					if jsonMap, ok := p.Value.(JsonMap); ok {
						if obj, ok := jsonMap["object"].(string); ok {
							for _, anyOf := range prop.Value.AnyOf {
								component := refKey(anyOf.Ref)
								if component == obj {
									typ := typeMap[makeTypeName(component)]
									if typ != nil {
										return typ.(*graphql.Object)
									}
								}
							}
						}
					}
					return nil
				},
			})
			typeMap[typeName] = typ
			baseType = typ
		}

	}

	if baseType != nil && slices.Contains(schema.Value.Required, propertyName) {
		baseType = graphql.NewNonNull(baseType)
	}

	return baseType

}

func genTypeFromSchemaRef(
	loader *openapi3.T,
	typeMap TypeMap,
	schemaName string,
	schema *openapi3.SchemaRef,
) *graphql.Object {

	if len(schema.Value.Properties) == 0 {
		return nil
	}

	typeName := makeTypeName(schemaName)

	fieldsThunk := (graphql.FieldsThunk)(func() graphql.Fields {
		fields := make(graphql.Fields)
		for propertyName, prop := range schema.Value.Properties {
			propertyName := propertyName
			prop := prop
			typ := typeOfProp(loader, typeMap, schemaName, schema, propertyName, prop)

			needsIdFetcher := slices.ContainsFunc(prop.Value.AnyOf, func(anyOf *openapi3.SchemaRef) bool {
				return anyOf.Value.Type == "string"
			})

			if typ != nil {
				propertyName := propertyName
				fieldName := makeFieldName(propertyName)
				fields[fieldName] = &graphql.Field{
					Name:        fieldName,
					Description: prop.Value.Description,
					Type:        typ,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
						if !ok {
							return nil, fmt.Errorf("missing required context")
						}

						if jsonMap, ok := p.Source.(JsonMap); ok {
							val := jsonMap[propertyName]
							if needsIdFetcher {
								if id, ok := val.(string); ok {
									anyOfs := prop.Value.AnyOf
									idComponents := strings.Split(id, "_")
									if len(idComponents) == 2 {
										slices.SortFunc(prop.Value.AnyOf, func(a *openapi3.SchemaRef, b *openapi3.SchemaRef) bool {
											if a.Ref != "" && refKey(a.Ref) == idComponents[0] {
												return true
											} else if b.Ref != "" && refKey(b.Ref) == idComponents[0] {
												return false
											} else {
												return false
											}
										})
									}
									for _, anyOf := range anyOfs {
										if anyOf.Ref != "" {
											path := fmt.Sprintf("/v1/%s/{id}", inflection.Plural(refKey(anyOf.Ref)))
											parentPath := fmt.Sprintf(
												"/v1/%s/{parentId}/%s/{id}",
												inflection.Plural(schemaName),
												inflection.Plural(refKey(anyOf.Ref)),
											)
											if loader.Paths.Find(path) != nil {
												res, err := stripeFetch(strings.Replace(path, "{id}", id, 1), emptyParams)
												if err == nil {
													return res, nil
												}
											} else if loader.Paths.Find(parentPath) != nil {
												if parentId, ok := jsonMap["id"].(string); ok {
													res, err := stripeFetch(
														strings.Replace(
															strings.Replace(parentPath, "{id}", id, 1),
															"{parentId}",
															parentId,
															1,
														),
														emptyParams,
													)
													if err == nil {
														return res, nil
													}
												}
											}
										}
									}
								}
							}
							return val, nil
						}
						return nil, nil
					},
				}
			}
		}

		if childFields, ok := childConnections[schemaName]; ok {
			for _, child := range childFields {
				child := child
				fieldName := strcase.ToLowerCamel(inflection.Plural(child))

				typ := typeMap[strcase.ToCamel(fmt.Sprintf("%s-connection", fieldName))]
				if typ == nil {
					log.Fatalf("Could not find connection type for %s on %s", child, schemaName)
				}

				path := fmt.Sprintf("/v1/%s", inflection.Plural(child))

				loaderPath := loader.Paths.Find(path)
				if loaderPath == nil {
					log.Fatalf("Could not find path in loader for %s on %s", child, schemaName)
				}

				if loaderPath.Get.Parameters.GetByInAndName("query", schemaName) == nil {
					log.Fatalf("could not find a path that takes %s as an argument on %s", schemaName, path)
				}

				args := graphql.FieldConfigArgument{
					"first": &graphql.ArgumentConfig{
						Type: graphql.Int,
					},
					"before": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
					"after": &graphql.ArgumentConfig{
						Type: graphql.String,
					},
				}

				if extra, ok := extraArgs[child]; ok {
					for _, arg := range extra {
						if arg.param != schemaName {
							argTyp := graphql.String
							if arg.typ != nil {
								argTyp = arg.typ
							}
							args[arg.fieldName] = &graphql.ArgumentConfig{
								Type: argTyp,
							}
						}
					}
				}

				fields[fieldName] = &graphql.Field{
					Name: fieldName,
					Type: typ,
					Args: args,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
						if !ok {
							return nil, fmt.Errorf("missing required context")
						}
						if jsonMap, ok := p.Source.(JsonMap); ok {
							if parentId, ok := jsonMap["id"].(string); ok {
								params := make(map[string]string, 0)
								params[schemaName] = parentId
								if first, ok := p.Args["first"].(int); ok {
									params["limit"] = strconv.Itoa(first)
								}
								if before, ok := p.Args["before"].(string); ok {
									params["ending_before"] = before
								}
								if after, ok := p.Args["after"].(string); ok {
									params["starting_after"] = after
								}
								if extra, ok := extraArgs[child]; ok {
									for _, arg := range extra {
										argTyp := graphql.String
										if arg.typ != nil {
											argTyp = arg.typ
										}
										switch argTyp {
										case graphql.Boolean:
											if field, ok := p.Args[arg.fieldName].(bool); ok {
												params[arg.param] = strconv.FormatBool(field)
											}
										case graphql.String:
											if field, ok := p.Args[arg.fieldName].(string); ok {
												params[arg.param] = field
											}
										default:
											log.Printf("Unknown arg type for extra arg %s on %s", arg.fieldName, child)
										}
									}
								}

								return stripeFetch(path, params)
							}
						}
						return nil, nil
					},
				}

			}
		}

		if schemaName == "charge" {
			fields["dispute"] = &graphql.Field{
				Name: "dispute",
				Type: typeMap["Dispute"],
				Resolve: func(p graphql.ResolveParams) (interface{}, error) {
					stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
					if !ok {
						return nil, fmt.Errorf("missing required context")
					}
					if jsonMap, ok := p.Source.(JsonMap); ok {
						if chargeId, ok := jsonMap["id"].(string); ok {
							if disputed, ok := jsonMap["disputed"].(bool); ok {
								if disputed {
									resp, err := stripeFetch("/v1/disputes", map[string]string{"charge": chargeId})
									if err != nil {
										return nil, err
									}
									if data, ok := resp["data"].([]interface{}); ok {
										if len(data) > 0 {
											if dispute, ok := data[0].(JsonMap); ok {
												return dispute, nil
											}
										}
									}
								}
							}
						}
					}
					return nil, nil
				},
			}
		}
		return fields
	})
	return graphql.NewObject(graphql.ObjectConfig{
		Name:        typeName,
		Description: schema.Value.Description,
		Fields:      (graphql.FieldsThunk)(fieldsThunk),
	})
}
func genSchema(loader *openapi3.T) graphql.Schema {
	typeMap := make(map[string]graphql.Type)

	for schemaName, schema := range loader.Components.Schemas {
		typ := genTypeFromSchemaRef(loader, typeMap, schemaName, schema)
		if typ != nil {
			typeMap[typ.Name()] = typ
		}
	}

	rootFields := graphql.Fields{}

	for _, singluarField := range singularRootFields {
		singluarField := singluarField
		typeName := makeTypeName(singluarField)
		fieldName := makeFieldName(singluarField)

		typ := typeMap[typeName]
		if typ == nil {
			log.Fatalf("Could not find type for singular field %s", singluarField)
		}
		// TODO: Generalize this paths thing a bit
		path := fmt.Sprintf("/v1/%s/{id}", inflection.Plural(strings.ReplaceAll(singluarField, ".", "/")))
		if loader.Paths.Find(path) == nil {
			path = strings.ReplaceAll(path, "_", "/")
			if loader.Paths.Find(path) == nil {
				log.Fatalf("Could not find a valid path for singular field %s", singluarField)
			}
		}
		rootFields[fieldName] = &graphql.Field{
			Name: fieldName,
			Type: typ,
			Args: graphql.FieldConfigArgument{
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
				if !ok {
					return nil, fmt.Errorf("missing required context")
				}
				return stripeFetch(strings.Replace(path, "{id}", p.Args["id"].(string), 1), emptyParams)
			},
		}
	}

	for _, customerNestedField := range customerNestedRootFields {
		customerNestedField := customerNestedField
		typeName := makeTypeName(customerNestedField)
		fieldName := makeFieldName(customerNestedField)

		typ := typeMap[typeName]
		if typ == nil {
			log.Fatalf("Could not find type for customer nested field %s", customerNestedField)
		}
		path := fmt.Sprintf("/v1/customers/{customerId}/%s/{id}", inflection.Plural(customerNestedField))
		if loader.Paths.Find(path) == nil {
			log.Fatalf("Could not find a valid path for customer nested field %s", customerNestedField)
		}
		rootFields[fieldName] = &graphql.Field{
			Name: fieldName,
			Type: typ,
			Args: graphql.FieldConfigArgument{
				"customer": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
				"id": &graphql.ArgumentConfig{
					Type: graphql.NewNonNull(graphql.String),
				},
			},
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
				if !ok {
					return nil, fmt.Errorf("missing required context")
				}
				return stripeFetch(strings.Replace(
					strings.Replace(path, "{id}", p.Args["id"].(string), 1),
					"{customerId}",
					p.Args["customer"].(string),
					1,
				),
					emptyParams,
				)
			},
		}
	}

	for _, pluralField := range pluralRootFields {
		pluralField := pluralField
		fieldName := makeFieldName(inflection.Plural(pluralField))

		typ := typeMap[makeTypeName(pluralField)]
		if typ == nil {
			log.Fatalf("Could not find type for plural field %s", pluralField)
		}

		path := fmt.Sprintf("/v1/%s", inflection.Plural(strings.ReplaceAll(pluralField, ".", "/")))
		if loader.Paths.Find(path) == nil {

			if loader.Paths.Find(path) == nil {
				log.Fatalf("Could not find a valid path for plural field %s", pluralField)
			}
		}

		connectionTypeName := strcase.ToCamel(fmt.Sprintf("%s-connection", inflection.Plural(pluralField)))
		edgeTypeName := strcase.ToCamel(fmt.Sprintf("%s-edge", inflection.Plural(pluralField)))

		edge := graphql.NewObject(graphql.ObjectConfig{
			Name: edgeTypeName,
			Fields: graphql.Fields{
				"node": &graphql.Field{
					Type: graphql.NewNonNull(typ),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						return p.Source, nil
					},
				},
				"cursor": &graphql.Field{
					Type: graphql.NewNonNull(graphql.String),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if jsonMap, ok := p.Source.(JsonMap); ok {
							return jsonMap["id"], nil
						}
						return nil, nil
					},
				},
			},
		})

		connection := graphql.NewObject(graphql.ObjectConfig{
			Name: connectionTypeName,
			Fields: graphql.Fields{
				"debug": &graphql.Field{
					Type: jsonObj,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						return p.Source, nil
					},
				},
				"cursor": &graphql.Field{
					Type: graphql.String,
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if jsonMap, ok := p.Source.(JsonMap); ok {
							if data, ok := jsonMap["data"].([]interface{}); ok {
								if len(data) > 0 {
									if f, ok := data[0].(JsonMap); ok {
										return f["id"], nil
									}
								}
							}
						}
						return nil, nil
					},
				},
				"nodes": &graphql.Field{
					Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(typ))),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if jsonMap, ok := p.Source.(JsonMap); ok {
							if data, ok := jsonMap["data"].([]interface{}); ok {
								return data, nil
							}
						}
						empty := make([]interface{}, 0)
						return empty, nil
					},
				},
				"edges": &graphql.Field{
					Type: graphql.NewNonNull(graphql.NewList(graphql.NewNonNull(edge))),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if jsonMap, ok := p.Source.(JsonMap); ok {
							if data, ok := jsonMap["data"].([]interface{}); ok {
								return data, nil
							}
						}
						empty := make([]interface{}, 0)
						return empty, nil
					},
				},
				"pageInfo": &graphql.Field{
					Type: graphql.NewNonNull(pageInfo),
					Resolve: func(p graphql.ResolveParams) (interface{}, error) {
						if jsonMap, ok := p.Source.(JsonMap); ok {
							pageInfo := PageInfo{
								HasPreviousPage: false,
							}
							if hasNextPage, ok := jsonMap["has_more"].(bool); ok {
								pageInfo.HasNextPage = hasNextPage
							}
							if data, ok := jsonMap["data"].([]interface{}); ok {
								if len(data) > 0 {
									if f, ok := data[0].(JsonMap); ok {
										if id, ok := f["id"].(string); ok {
											pageInfo.StartCursor = id
										}
									}
									if f, ok := data[len(data)-1].(JsonMap); ok {
										if id, ok := f["id"].(string); ok {
											pageInfo.EndCursor = id
										}
									}
								}
							}
							return pageInfo, nil
						}
						return nil, nil
					},
				},
			},
		})

		typeMap[connectionTypeName] = connection

		args := graphql.FieldConfigArgument{
			"first": &graphql.ArgumentConfig{
				Type: graphql.Int,
			},
			"before": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
			"after": &graphql.ArgumentConfig{
				Type: graphql.String,
			},
		}

		if extra, ok := extraArgs[pluralField]; ok {
			for _, arg := range extra {
				argTyp := graphql.String
				if arg.typ != nil {
					argTyp = arg.typ
				}
				args[arg.fieldName] = &graphql.ArgumentConfig{
					Type: argTyp,
				}
			}
		}

		rootFields[fieldName] = &graphql.Field{
			Name: fieldName,
			Type: connection,
			Args: args,
			Resolve: func(p graphql.ResolveParams) (interface{}, error) {
				stripeFetch, ok := p.Context.Value(stripeFetchKey).(stripeFetch)
				if !ok {
					return nil, fmt.Errorf("missing required context")
				}
				params := make(map[string]string, 0)
				if first, ok := p.Args["first"].(int); ok {
					params["limit"] = strconv.Itoa(first)
				}
				if before, ok := p.Args["before"].(string); ok {
					params["ending_before"] = before
				}
				if after, ok := p.Args["after"].(string); ok {
					params["starting_after"] = after
				}
				if extra, ok := extraArgs[pluralField]; ok {
					for _, arg := range extra {
						argTyp := graphql.String
						if arg.typ != nil {
							argTyp = arg.typ
						}
						switch argTyp {
						case graphql.Boolean:
							if field, ok := p.Args[arg.fieldName].(bool); ok {
								params[arg.param] = strconv.FormatBool(field)
							}
						case graphql.String:
							if field, ok := p.Args[arg.fieldName].(string); ok {
								params[arg.param] = field
							}
						default:
							log.Printf("Unknown arg type for extra arg %s on %s", arg.fieldName, connectionTypeName)
						}
					}
				}
				return stripeFetch(path, params)
			},
		}
	}

	rootQuery := graphql.ObjectConfig{Name: "Query", Fields: rootFields}

	schemaConfig := graphql.SchemaConfig{Query: graphql.NewObject(rootQuery)}

	schema, err := graphql.NewSchema(schemaConfig)
	if err != nil {
		log.Fatalf("failed to create new schema, error: %v", err)
	}

	return schema
}

//go:embed openapi/openapi/spec3.json
var staticFS embed.FS

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.LstdFlags | log.Lshortfile)
	log.Print("starting server...")
	spec, err := staticFS.ReadFile("openapi/openapi/spec3.json")
	if err != nil {
		log.Fatalf("Error opening openapi spec %v", err)
	}
	loader, err := openapi3.NewLoader().LoadFromData(spec)
	if err != nil {
		log.Fatalf("Error loading openapi spec %v", err)
	}
	schema := genSchema(loader)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	h := handler.New(&handler.Config{
		Schema:     &schema,
		Pretty:     true,
		GraphiQL:   false,
		Playground: true,
	})

	r.Get("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/graphql", 302)
	}))

	r.Get("/graphql", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
	}))
	r.Post("/graphql", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		stripeToken := ""
		authorization := strings.Split(r.Header.Get("Authorization"), " ")
		stripeTokenHeader := r.Header.Get("X-Stripe-Token")
		if len(authorization) == 2 && authorization[0] == "Bearer" {
			stripeToken = authorization[1]
		} else if stripeTokenHeader != "" {
			stripeToken = stripeTokenHeader
		}
		stripeFetch := makeStripeFetch(stripeToken)
		ctx := context.WithValue(r.Context(), stripeFetchKey, stripeFetch)
		h.ServeHTTP(w, r.WithContext(ctx))
	}))

	port := os.Getenv("PORT")
	if port == "" {
		port = "8092"
	}

	var addr string
	if os.Getenv("ENV") == "production" {
		addr = fmt.Sprintf(":%s", port)

	} else {
		addr = fmt.Sprintf("127.0.0.1:%s", port)
	}
	log.Printf("listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, r))
}
