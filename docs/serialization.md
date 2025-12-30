# Serialization Formats

SD-JWT supports multiple serialization formats for different use cases.

## Compact Serialization (Default)

The compact format is a tilde-separated string, suitable for URL parameters and HTTP headers.

```
# SD-JWT (without key binding)
<issuer-signed-jwt>~<disclosure1>~<disclosure2>~...~<disclosureN>~

# SD-JWT with Key Binding
<issuer-signed-jwt>~<disclosure1>~...~<disclosureN>~<key-binding-jwt>
```

### Example

```go
// Serialize
compact := sdJWT.Serialize()
// eyJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiLi4uIl19.sig~WyJzYWx0IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ~

// Parse
sdJWT, kbJWT, _ := sdjwt.Parse(compact, "sha-256")
```

## Flattened JSON Serialization

Uses the JWS Flattened JSON format, suitable for JSON-based protocols.

```json
{
    "protected": "<base64url header>",
    "payload": "<base64url payload>",
    "signature": "<base64url signature>",
    "header": {
        "disclosures": ["<disclosure1>", "<disclosure2>", ...],
        "kb_jwt": "<key-binding-jwt>"  // optional
    }
}
```

### Example

```go
// Serialize
flatJSON, _ := sdJWT.SerializeFlattenJSON()

// With key binding
presentation := holder.SerializePresentation(pres)
flatJSON, _ := sdjwt.FlattenJSONFromCompact(presentation)

// Parse
sdJWT, kbJWT, _ := sdjwt.ParseFlattenJSON(flatJSON, "sha-256")
```

## General JSON Serialization

Uses the JWS General JSON format, supporting multiple signatures.

```json
{
    "payload": "<base64url payload>",
    "signatures": [
        {
            "protected": "<base64url header>",
            "signature": "<base64url signature>",
            "header": {
                "disclosures": ["<disclosure1>", "<disclosure2>", ...],
                "kb_jwt": "<key-binding-jwt>"  // optional
            }
        }
    ]
}
```

### Example

```go
// Serialize
generalJSON, _ := sdJWT.SerializeGeneralJSON()

// Parse
sdJWT, kbJWT, _ := sdjwt.ParseGeneralJSON(generalJSON, "sha-256")
```

## Converting Between Formats

```go
// Get the internal structure
flat, _ := sdJWT.ToFlattenJSON()
general, _ := sdJWT.ToGeneralJSON()

// Serialize structures to JSON strings
flatStr, _ := json.Marshal(flat)
generalStr, _ := json.Marshal(general)

// Parse from JSON
var flatStruct sdjwt.FlattenJSON
json.Unmarshal(flatStr, &flatStruct)
sdJWT, kbJWT, _ := sdjwt.FromFlattenJSON(&flatStruct, "sha-256")
```

## Format Comparison

| Feature | Compact | Flattened JSON | General JSON |
|---------|---------|----------------|--------------|
| Size | Smallest | Medium | Largest |
| URL safe | Yes | No | No |
| Multiple signatures | No | No | Yes |
| Easy to parse | Medium | Easy | Easy |
| Human readable | No | Yes | Yes |
| Use case | Transport | APIs | Multi-party |

## Best Practices

1. **Use Compact** for HTTP headers, URL parameters, and QR codes
2. **Use Flattened JSON** for REST APIs and JSON-based storage
3. **Use General JSON** when multiple signatures are needed

## Handling Presentations

Presentations include disclosures and optionally a key binding JWT:

```go
// Create presentation
presentation, _ := h.PresentWithFrame(presFrame, key, method, kbOptions)

// Serialize to compact
compact := holder.SerializePresentation(presentation)

// Parse presentation
sdJWT, kbJWT, _ := sdjwt.Parse(compact, "sha-256")

// kbJWT is the key binding JWT if present
if kbJWT != "" {
    // Verify key binding
}
```
