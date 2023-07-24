package wafv2

import (
	"math"
	"regexp"

	"github.com/aws/aws-sdk-go/service/wafv2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
	"github.com/hashicorp/terraform-provider-aws/internal/verify"
)

func emptySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{},
		},
	}
}

func ruleLabelsSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 1024),
						validation.StringMatch(regexp.MustCompile(`^[0-9A-Za-z_\-:]+$`), "must contain only alphanumeric, underscore, hyphen, and colon characters"),
					),
				},
			},
		},
	}
}

func ruleGroupRootStatementSchema(level int) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"and_statement":                         statementSchema(level),
				"byte_match_statement":                  byteMatchStatementSchema(),
				"geo_match_statement":                   geoMatchStatementSchema(),
				"ip_set_reference_statement":            ipSetReferenceStatementSchema(),
				"label_match_statement":                 labelMatchStatementSchema(),
				"not_statement":                         statementSchema(level),
				"or_statement":                          statementSchema(level),
				"rate_based_statement":                  rateBasedStatementSchema(level),
				"regex_match_statement":                 regexMatchStatementSchema(),
				"regex_pattern_set_reference_statement": regexPatternSetReferenceStatementSchema(),
				"size_constraint_statement":             sizeConstraintSchema(),
				"sqli_match_statement":                  sqliMatchStatementSchema(),
				"xss_match_statement":                   xssMatchStatementSchema(),
			},
		},
	}
}

func statementSchema(level int) *schema.Schema {
	if level > 1 {
		return &schema.Schema{
			Type:     schema.TypeList,
			Optional: true,
			MaxItems: 1,
			Elem: &schema.Resource{
				Schema: map[string]*schema.Schema{
					"statement": {
						Type:     schema.TypeList,
						Required: true,
						Elem: &schema.Resource{
							Schema: map[string]*schema.Schema{
								"and_statement":                         statementSchema(level - 1),
								"byte_match_statement":                  byteMatchStatementSchema(),
								"geo_match_statement":                   geoMatchStatementSchema(),
								"ip_set_reference_statement":            ipSetReferenceStatementSchema(),
								"label_match_statement":                 labelMatchStatementSchema(),
								"not_statement":                         statementSchema(level - 1),
								"or_statement":                          statementSchema(level - 1),
								"regex_match_statement":                 regexMatchStatementSchema(),
								"regex_pattern_set_reference_statement": regexPatternSetReferenceStatementSchema(),
								"size_constraint_statement":             sizeConstraintSchema(),
								"sqli_match_statement":                  sqliMatchStatementSchema(),
								"xss_match_statement":                   xssMatchStatementSchema(),
							},
						},
					},
				},
			},
		}
	}

	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"statement": {
					Type:     schema.TypeList,
					Required: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"byte_match_statement":                  byteMatchStatementSchema(),
							"geo_match_statement":                   geoMatchStatementSchema(),
							"ip_set_reference_statement":            ipSetReferenceStatementSchema(),
							"label_match_statement":                 labelMatchStatementSchema(),
							"regex_match_statement":                 regexMatchStatementSchema(),
							"regex_pattern_set_reference_statement": regexPatternSetReferenceStatementSchema(),
							"size_constraint_statement":             sizeConstraintSchema(),
							"sqli_match_statement":                  sqliMatchStatementSchema(),
							"xss_match_statement":                   xssMatchStatementSchema(),
						},
					},
				},
			},
		},
	}
}

func byteMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"field_to_match": fieldToMatchSchema(),
				"positional_constraint": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.PositionalConstraint_Values(), false),
				},
				"search_string": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringLenBetween(1, 200),
				},
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func geoMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"country_codes": {
					Type:     schema.TypeList,
					Required: true,
					MinItems: 1,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},
				"forwarded_ip_config": forwardedIPConfigSchema(),
			},
		},
	}
}

func ipSetReferenceStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"arn": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: verify.ValidARN,
				},
				"ip_set_forwarded_ip_config": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"fallback_behavior": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringInSlice(wafv2.FallbackBehavior_Values(), false),
							},
							"header_name": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 255),
									validation.StringMatch(regexp.MustCompile(`^[a-zA-Z0-9-]+$`), "must contain only alphanumeric and hyphen characters"),
								),
							},
							"position": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringInSlice(wafv2.ForwardedIPPosition_Values(), false),
							},
						},
					},
				},
			},
		},
	}
}

func labelMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"key": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 1024),
						validation.StringMatch(regexp.MustCompile(`^[0-9A-Za-z_\-:]+$`), "must contain only alphanumeric, underscore, hyphen, and colon characters"),
					),
				},
				"scope": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.LabelMatchScope_Values(), false),
				},
			},
		},
	}
}

func regexMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"regex_string": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 512),
						validation.StringIsValidRegExp,
					),
				},
				"field_to_match":      fieldToMatchSchema(),
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func regexPatternSetReferenceStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"arn": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: verify.ValidARN,
				},
				"field_to_match":      fieldToMatchSchema(),
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func sizeConstraintSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"comparison_operator": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.ComparisonOperator_Values(), false),
				},
				"field_to_match": fieldToMatchSchema(),
				"size": {
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntBetween(0, math.MaxInt32),
				},
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func sqliMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"field_to_match":      fieldToMatchSchema(),
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func xssMatchStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"field_to_match":      fieldToMatchSchema(),
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

// --------
func rateLimitHeaderSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 40),
						// The value is returned in lower case by the API.
						// Trying to solve it with StateFunc and/or DiffSuppressFunc resulted in hash problem of the rule field or didn't work.
						validation.StringMatch(regexp.MustCompile(`^[a-z0-9-_]+$`), "must contain only lowercase alphanumeric characters, underscores, and hyphens"),
					),
				},
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func rateLimitCookieSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 40),
						// The value is returned in lower case by the API.
						// Trying to solve it with StateFunc and/or DiffSuppressFunc resulted in hash problem of the rule field or didn't work.
						validation.StringMatch(regexp.MustCompile(`^[a-z0-9-_]+$`), "must contain only lowercase alphanumeric characters, underscores, and hyphens"),
					),
				},
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func rateLimitQueryArgumentSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"name": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 40),
						// The value is returned in lower case by the API.
						// Trying to solve it with StateFunc and/or DiffSuppressFunc resulted in hash problem of the rule field or didn't work.
						validation.StringMatch(regexp.MustCompile(`^[a-z0-9-_]+$`), "must contain only lowercase alphanumeric characters, underscores, and hyphens"),
					),
				},
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func rateLimitQueryStringSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

func rateLimitLabelNamespaceSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"namespace": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 1024),
						validation.StringMatch(regexp.MustCompile(`^[0-9A-Za-z_\-:]+:$`), "must contain only alphanumeric, underscore, hyphen, and colon characters"),
					),
				},
			},
		},
	}
}

func rateLimitUriPathSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"text_transformation": textTransformationSchema(),
			},
		},
	}
}

//----------------------------------
/*
   <!-- This field contains all the advanced rate based custom types .-->
   <structure name="RateBasedStatementCustomKey">
       <member name="Header" target="RateLimitHeader" />
       <member name="Cookie" target="RateLimitCookie" />
       <member name="QueryArgument" target="RateLimitQueryArgument" />
       <member name="QueryString" target="RateLimitQueryString" />
       <member name="HTTPMethod" target="RateLimitHTTPMethod" />
       <member name="ForwardedIP" target="RateLimitForwardedIP" />
       <member name="IP" target="RateLimitIP" />
       <member name="LabelNamespace" target="RateLimitLabelNamespace" />
       <member name="JA3Hash" target="RateLimitJA3Hash"/>
       <member name="UriPath" target="RateLimitUriPath" />
   </structure>

   <list name="RateBasedStatementCustomKeys">
       <member target="RateBasedStatementCustomKey"/>
   </list>
   <length target="RateBasedStatementCustomKeys">
       <max value="5"/>
   </length>

   <structure name="RateLimitIP" />
   <structure name="RateLimitForwardedIP" />
   <structure name="RateLimitHTTPMethod" />

   <structure name="RateLimitHeader">
       <member name="Name" target="FieldToMatchData" />
       <member name="TextTransformations" target="TextTransformations" />
   </structure>
   <required target="RateLimitHeader$Name" />
   <required target="RateLimitHeader$TextTransformations" />

   <structure name="RateLimitCookie">
       <member name="Name" target="FieldToMatchData" />
       <member name="TextTransformations" target="TextTransformations" />
   </structure>
   <required target="RateLimitCookie$Name" />
   <required target="RateLimitCookie$TextTransformations" />

   <structure name="RateLimitQueryArgument">
       <member name="Name" target="FieldToMatchData" />
       <member name="TextTransformations" target="TextTransformations" />
   </structure>
   <required target="RateLimitQueryArgument$Name" />
   <required target="RateLimitQueryArgument$TextTransformations" />

   <structure name="RateLimitQueryString">
       <member name="TextTransformations" target="TextTransformations" />
   </structure>
   <required target="RateLimitQueryString$TextTransformations" />


   <structure name="RateLimitLabelNamespace">
       <member name="Namespace" target="LabelNamespace" />
   </structure>
   <required target="RateLimitLabelNamespace$Namespace" />

   <structure name="RateLimitJA3Hash" >
       <member name="FallbackBehavior" target="FallbackBehavior" />
   </structure>
   <required target="RateLimitJA3Hash$FallbackBehavior" />

   <structure name="RateLimitUriPath">
       <member name="TextTransformations" target="TextTransformations" />
   </structure>
   <required target="RateLimitUriPath$TextTransformations" />


   <structure name="RateBasedStatementCustomKey">
       <member name="Header" target="RateLimitHeader" />
       <member name="Cookie" target="RateLimitCookie" />
       <member name="QueryArgument" target="RateLimitQueryArgument" />
       <member name="QueryString" target="RateLimitQueryString" />
       <member name="HTTPMethod" target="RateLimitHTTPMethod" />
       <member name="ForwardedIP" target="RateLimitForwardedIP" />
       <member name="IP" target="RateLimitIP" />
       <member name="LabelNamespace" target="RateLimitLabelNamespace" />
       <member name="JA3Hash" target="RateLimitJA3Hash"/>
       <member name="UriPath" target="RateLimitUriPath" />
   </structure>
*/

func rateBasedStatementCustomKeySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MinItems: 1,
		Elem:     rateBasedStatementCustomKeyBaseSchema(),
	}
}

// add list ratelimitcustomkeys
func rateBasedStatementCustomKeyBaseSchema() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"header":          rateLimitHeaderSchema(),
			"cookie":          rateLimitCookieSchema(),
			"query_argument":  rateLimitQueryArgumentSchema(),
			"query_string":    rateLimitQueryStringSchema(),
			"http_method":     emptySchema(),
			"forwarded_ip":    emptySchema(),
			"ip":              emptySchema(),
			"label_namespace": rateLimitLabelNamespaceSchema(),
			//"uri_path": emptySchema(),
		},
	}
}

//--------

func fieldToMatchBaseSchema() *schema.Resource {
	return &schema.Resource{
		Schema: map[string]*schema.Schema{
			"all_query_arguments": emptySchema(),
			"body":                bodySchema(),
			"cookies":             cookiesSchema(),
			"headers":             headersSchema(),
			"json_body":           jsonBodySchema(),
			"method":              emptySchema(),
			"query_string":        emptySchema(),
			"single_header": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 40),
								// The value is returned in lower case by the API.
								// Trying to solve it with StateFunc and/or DiffSuppressFunc resulted in hash problem of the rule field or didn't work.
								validation.StringMatch(regexp.MustCompile(`^[a-z0-9-_]+$`), "must contain only lowercase alphanumeric characters, underscores, and hyphens"),
							),
						},
					},
				},
			},
			"single_query_argument": {
				Type:     schema.TypeList,
				Optional: true,
				MaxItems: 1,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"name": {
							Type:     schema.TypeString,
							Required: true,
							ValidateFunc: validation.All(
								validation.StringLenBetween(1, 30),
								// The value is returned in lower case by the API.
								// Trying to solve it with StateFunc and/or DiffSuppressFunc resulted in hash problem of the rule field or didn't work.
								validation.StringMatch(regexp.MustCompile(`^[a-z0-9-_]+$`), "must contain only lowercase alphanumeric characters, underscores, and hyphens"),
							),
						},
					},
				},
			},
			"uri_path": emptySchema(),
		},
	}
}

func fieldToMatchSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem:     fieldToMatchBaseSchema(),
	}
}

func jsonBodySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"invalid_fallback_behavior": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringInSlice(wafv2.BodyParsingFallbackBehavior_Values(), false),
				},
				"match_pattern": jsonBodyMatchPatternSchema(),
				"match_scope": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.JsonMatchScope_Values(), false),
				},
				"oversize_handling": oversizeHandlingOptionalSchema(wafv2.OversizeHandlingContinue),
			},
		},
	}
}

func jsonBodyMatchPatternSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"all": emptySchema(),
				"included_paths": {
					Type:     schema.TypeList,
					Optional: true,
					MinItems: 1,
					Elem: &schema.Schema{
						Type: schema.TypeString,
						ValidateFunc: validation.All(
							validation.StringLenBetween(1, 512),
							validation.StringMatch(regexp.MustCompile(`(/)|(/(([^~])|(~[01]))+)`), "must be a valid JSON pointer")),
					},
				},
			},
		},
	}
}

func forwardedIPConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"fallback_behavior": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.FallbackBehavior_Values(), false),
				},
				"header_name": {
					Type:     schema.TypeString,
					Required: true,
				},
			},
		},
	}
}

//	TextTransformations []*TextTransformation `min:"1" type:"list" required:"true"`
//	CustomKeys []*RateBasedStatementCustomKey `min:"1" type:"list"`------------------

func textTransformationSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Required: true,
		MinItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"priority": {
					Type:     schema.TypeInt,
					Required: true,
				},
				"type": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.TextTransformationType_Values(), false),
				},
			},
		},
	}
}

func visibilityConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"cloudwatch_metrics_enabled": {
					Type:     schema.TypeBool,
					Required: true,
				},
				"metric_name": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 128),
						validation.StringMatch(regexp.MustCompile(`^[a-zA-Z0-9-_]+$`), "must contain only alphanumeric hyphen and underscore characters"),
					),
				},
				"sampled_requests_enabled": {
					Type:     schema.TypeBool,
					Required: true,
				},
			},
		},
	}
}

func allowConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_request_handling": customRequestHandlingSchema(),
			},
		},
	}
}

func captchaConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_request_handling": customRequestHandlingSchema(),
			},
		},
	}
}

func outerCaptchaConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"immunity_time_property": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"immunity_time": {
								Type:     schema.TypeInt,
								Optional: true,
							},
						},
					},
				},
			},
		},
	}
}

func challengeConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_request_handling": customRequestHandlingSchema(),
			},
		},
	}
}

func countConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_request_handling": customRequestHandlingSchema(),
			},
		},
	}
}

func blockConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_response": customResponseSchema(),
			},
		},
	}
}

func customRequestHandlingSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"insert_header": {
					Type:     schema.TypeSet,
					Required: true,
					MinItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 64),
									validation.StringMatch(regexp.MustCompile(`^[a-zA-Z0-9._$-]+$`), "must contain only alphanumeric, hyphen, underscore, dot and $ characters"),
								),
							},
							"value": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringLenBetween(1, 255),
							},
						},
					},
				},
			},
		},
	}
}

func customResponseSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"custom_response_body_key": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 128),
						validation.StringMatch(regexp.MustCompile(`^[\w\-]+$`), "must contain only alphanumeric, hyphen, and underscore characters"),
					),
				},
				"response_code": {
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntBetween(200, 600),
				},
				"response_header": {
					Type:     schema.TypeSet,
					Optional: true,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"name": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 64),
									validation.StringMatch(regexp.MustCompile(`^[a-zA-Z0-9._$-]+$`), "must contain only alphanumeric, hyphen, underscore, dot and $ characters"),
								),
							},
							"value": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringLenBetween(1, 255),
							},
						},
					},
				},
			},
		},
	}
}

func customResponseBodySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeSet,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"key": {
					Type:     schema.TypeString,
					Required: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 128),
						validation.StringMatch(regexp.MustCompile(`^[\w\-]+$`), "must contain only alphanumeric, hyphen, and underscore characters"),
					),
				},
				"content": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringLenBetween(1, 10240),
				},
				"content_type": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.ResponseContentType_Values(), false),
				},
			},
		},
	}
}

func cookiesSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"match_scope":       matchScopeSchema(),
				"oversize_handling": oversizeHandlingRequiredSchema(),
				"match_pattern":     cookiesMatchPatternSchema(),
			},
		},
	}
}

func cookiesMatchPatternSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"all": emptySchema(),
				"excluded_cookies": {
					Type:     schema.TypeList,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},
				"included_cookies": {
					Type:     schema.TypeList,
					Optional: true,
					Elem:     &schema.Schema{Type: schema.TypeString},
				},
			},
		},
	}
}

func bodySchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"oversize_handling": oversizeHandlingOptionalSchema(wafv2.OversizeHandlingContinue),
			},
		},
	}
}

func oversizeHandlingOptionalSchema(defaultValue string) *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Optional:     true,
		Default:      defaultValue,
		ValidateFunc: validation.StringInSlice(wafv2.OversizeHandling_Values(), false),
	}
}

func oversizeHandlingRequiredSchema() *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringInSlice(wafv2.OversizeHandling_Values(), false),
	}
}

func matchScopeSchema() *schema.Schema {
	return &schema.Schema{
		Type:         schema.TypeString,
		Required:     true,
		ValidateFunc: validation.StringInSlice(wafv2.MapMatchScope_Values(), false),
	}
}

func headersSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"match_pattern": {
					Type:     schema.TypeList,
					Required: true,
					MaxItems: 1,
					MinItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"all":              emptySchema(),
							"excluded_headers": headersMatchPatternBaseSchema(),
							"included_headers": headersMatchPatternBaseSchema(),
						},
					},
				},
				"match_scope":       matchScopeSchema(),
				"oversize_handling": oversizeHandlingRequiredSchema(),
			},
		},
	}
}

func headersMatchPatternBaseSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MinItems: 1,
		MaxItems: 199,
		Elem: &schema.Schema{
			Type: schema.TypeString,
			ValidateFunc: validation.All(
				validation.StringLenBetween(1, 64),
				validation.StringMatch(regexp.MustCompile(`.*\S.*`), ""),
			),
		},
	}
}

func webACLRootStatementSchema(level int) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"and_statement":                         statementSchema(level),
				"byte_match_statement":                  byteMatchStatementSchema(),
				"geo_match_statement":                   geoMatchStatementSchema(),
				"ip_set_reference_statement":            ipSetReferenceStatementSchema(),
				"label_match_statement":                 labelMatchStatementSchema(),
				"managed_rule_group_statement":          managedRuleGroupStatementSchema(level),
				"not_statement":                         statementSchema(level),
				"or_statement":                          statementSchema(level),
				"rate_based_statement":                  rateBasedStatementSchema(level),
				"regex_match_statement":                 regexMatchStatementSchema(),
				"regex_pattern_set_reference_statement": regexPatternSetReferenceStatementSchema(),
				"rule_group_reference_statement":        ruleGroupReferenceStatementSchema(),
				"size_constraint_statement":             sizeConstraintSchema(),
				"sqli_match_statement":                  sqliMatchStatementSchema(),
				"xss_match_statement":                   xssMatchStatementSchema(),
			},
		},
	}
}

func managedRuleGroupStatementSchema(level int) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"managed_rule_group_configs": managedRuleGroupConfigSchema(),
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringLenBetween(1, 128),
				},
				"rule_action_override": ruleActionOverrideSchema(),
				"scope_down_statement": scopeDownStatementSchema(level - 1),
				"vendor_name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringLenBetween(1, 128),
				},
				"version": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringLenBetween(1, 128),
				},
			},
		},
	}
}

func rateBasedStatementSchema(level int) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"aggregate_key_type": {
					Type:         schema.TypeString,
					Optional:     true,
					Default:      wafv2.RateBasedStatementAggregateKeyTypeIp,
					ValidateFunc: validation.StringInSlice(wafv2.RateBasedStatementAggregateKeyType_Values(), false),
				},
				"forwarded_ip_config": forwardedIPConfigSchema(),
				"limit": {
					Type:         schema.TypeInt,
					Required:     true,
					ValidateFunc: validation.IntBetween(100, 2000000000),
				},
				"scope_down_statement": scopeDownStatementSchema(level - 1),
				"custom_keys":          rateBasedStatementCustomKeySchema(),
			},
		},
	}
}

func scopeDownStatementSchema(level int) *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"and_statement":                         statementSchema(level),
				"byte_match_statement":                  byteMatchStatementSchema(),
				"geo_match_statement":                   geoMatchStatementSchema(),
				"label_match_statement":                 labelMatchStatementSchema(),
				"ip_set_reference_statement":            ipSetReferenceStatementSchema(),
				"not_statement":                         statementSchema(level),
				"or_statement":                          statementSchema(level),
				"regex_match_statement":                 regexMatchStatementSchema(),
				"regex_pattern_set_reference_statement": regexPatternSetReferenceStatementSchema(),
				"size_constraint_statement":             sizeConstraintSchema(),
				"sqli_match_statement":                  sqliMatchStatementSchema(),
				"xss_match_statement":                   xssMatchStatementSchema(),
			},
		},
	}
}

func ruleActionOverrideSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 100,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"action_to_use": actionToUseSchema(),
				"name": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringLenBetween(1, 128),
				},
			},
		},
	}
}

func managedRuleGroupConfigSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"aws_managed_rules_bot_control_rule_set": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"inspection_level": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringInSlice(wafv2.InspectionLevel_Values(), false),
							},
						},
					},
				},
				"aws_managed_rules_atp_rule_set": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"login_path": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 256),
									validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
								),
							},
							"request_inspection":  managedRuleGroupConfigATPRequestInspectionSchema(),
							"response_inspection": managedRuleGroupConfigATPResponseInspectionSchema(),
						},
					},
				},
				"login_path": {
					Type:     schema.TypeString,
					Optional: true,
					ValidateFunc: validation.All(
						validation.StringLenBetween(1, 256),
						validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
					),
				},
				"password_field": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"identifier": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 512),
									validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
								),
							},
						},
					},
				},
				"payload_type": {
					Type:         schema.TypeString,
					Optional:     true,
					ValidateFunc: validation.StringInSlice(wafv2.PayloadType_Values(), false),
				},
				"username_field": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"identifier": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 512),
									validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
								),
							},
						},
					},
				},
			},
		},
	}
}

func actionToUseSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Required: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"allow":   allowConfigSchema(),
				"block":   blockConfigSchema(),
				"captcha": captchaConfigSchema(),
				"count":   countConfigSchema(),
			},
		},
	}
}

func ruleGroupReferenceStatementSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"arn": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: verify.ValidARN,
				},
				"rule_action_override": ruleActionOverrideSchema(),
			},
		},
	}
}

func managedRuleGroupConfigATPRequestInspectionSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"password_field": {
					Type:     schema.TypeList,
					Required: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"identifier": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 512),
									validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
								),
							},
						},
					},
				},
				"payload_type": {
					Type:         schema.TypeString,
					Required:     true,
					ValidateFunc: validation.StringInSlice(wafv2.PayloadType_Values(), false),
				},
				"username_field": {
					Type:     schema.TypeList,
					Required: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"identifier": {
								Type:     schema.TypeString,
								Required: true,
								ValidateFunc: validation.All(
									validation.StringLenBetween(1, 512),
									validation.StringMatch(regexp.MustCompile(`.*\S.*`), `must conform to pattern .*\S.* `),
								),
							},
						},
					},
				},
			},
		},
	}
}

func managedRuleGroupConfigATPResponseInspectionSchema() *schema.Schema {
	return &schema.Schema{
		Type:     schema.TypeList,
		Optional: true,
		MaxItems: 1,
		Elem: &schema.Resource{
			Schema: map[string]*schema.Schema{
				"body_contains": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"failure_strings": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
							},
							"success_strings": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
							},
						},
					},
				},
				"header": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"failure_values": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
								// TODO: ValidateFunc: length > 0
							},
							"name": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringLenBetween(1, 256),
							},
							"success_values": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
								// TODO: ValidateFunc: length > 0
							},
						},
					},
				},
				"json": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"failure_values": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
								// TODO: ValidateFunc: length > 0
							},
							"identifier": {
								Type:         schema.TypeString,
								Required:     true,
								ValidateFunc: validation.StringLenBetween(1, 256),
							},
							"success_values": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeString},
								// TODO: ValidateFunc: length > 0
							},
						},
					},
				},
				"status_code": {
					Type:     schema.TypeList,
					Optional: true,
					MaxItems: 1,
					Elem: &schema.Resource{
						Schema: map[string]*schema.Schema{
							"failure_codes": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeInt},
								// TODO: ValidateFunc: length > 0
							},
							"success_codes": {
								Type:     schema.TypeSet,
								Required: true,
								Elem:     &schema.Schema{Type: schema.TypeInt},
								// TODO: ValidateFunc: length > 0
							},
						},
					},
				},
			},
		},
	}
}
