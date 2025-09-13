# Digital Certificate System API Documentation

## Overview

Il sistema di certificazione digitale fornisce API RESTful per la generazione, verifica, download e gestione di certificati digitali firmati crittograficamente. Il sistema utilizza firme digitali RSA/ECDSA per garantire l'autenticità dei certificati senza richiedere tecnologia blockchain.

### Base URL
```
http://localhost:3000/certificates
```

### Autenticazione
La maggior parte degli endpoint richiede autenticazione JWT tramite header `Authorization: Bearer <token>`. L'endpoint di verifica è pubblico e non richiede autenticazione.

### Formati di Risposta
Tutte le risposte seguono il formato `ApiResponseDto`:

```typescript
{
  "success": boolean,
  "data": T | null,
  "message": string,
  "error"?: string,
  "statusCode"?: number,
  "timestamp"?: string
}
```

---

## Endpoints

### 1. Genera Certificato

**POST** `/certificates`

Genera un nuovo certificato digitale per un utente. Richiede privilegi di amministratore.

#### Headers
```
Authorization: Bearer <admin-jwt-token>
Content-Type: multipart/form-data
```

#### Request Body (Form Data)
| Campo | Tipo | Richiesto | Descrizione |
|-------|------|-----------|-------------|
| `user_uuid` | string (UUID) | ✅ | UUID dell'utente destinatario |
| `course_name` | string | ✅ | Nome del corso (max 255 caratteri) |
| `description` | string | ❌ | Descrizione opzionale (max 1000 caratteri) |
| `issued_date` | string (ISO) | ❌ | Data di emissione (default: ora corrente) |
| `metadata` | string (JSON) | ❌ | Metadati aggiuntivi in formato JSON |
| `certificate_file` | file | ✅ | File certificato (PDF/JSON, max 10MB) |

#### Response (201 Created)
```json
{
  "success": true,
  "data": {
    "id": "123e4567-e89b-12d3-a456-426614174000",
    "user_uuid": "user-uuid-123",
    "user_email": "user@example.com",
    "course_name": "Advanced TypeScript Development",
    "description": "Corso completo su TypeScript avanzato",
    "issued_date": "2024-01-15T10:30:00.000Z",
    "file_path": "certificates/2024/01/user-uuid/cert-id.pdf",
    "original_filename": "typescript-certificate.pdf",
    "content_type": "application/pdf",
    "file_size": 1048576,
    "public_key_id": "rsa-2024-01",
    "revoked": false,
    "revoked_at": null,
    "revoked_reason": null,
    "metadata": {},
    "created_at": "2024-01-15T10:30:00.000Z",
    "updated_at": "2024-01-15T10:30:00.000Z"
  },
  "message": "Certificate generated successfully"
}
```

#### Errori
- `400 Bad Request`: Dati di input non validi o file mancante
- `401 Unauthorized`: Token JWT mancante o non valido
- `403 Forbidden`: Privilegi insufficienti (richiesto ruolo admin)
- `404 Not Found`: Utente non trovato
- `500 Internal Server Error`: Errore durante la generazione

#### Esempio cURL
```bash
curl -X POST http://localhost:3000/certificates \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -F "user_uuid=123e4567-e89b-12d3-a456-426614174000" \
  -F "course_name=Advanced TypeScript Development" \
  -F "description=Corso completo su TypeScript avanzato" \
  -F "certificate_file=@certificate.pdf"
```

---

### 2. Verifica Certificato

**GET** `/certificates/{id}/verify`

Verifica l'autenticità di un certificato utilizzando il suo ID. Endpoint pubblico che non richiede autenticazione.

#### Parameters
| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| `id` | string (UUID) | ID del certificato da verificare |

#### Response (200 OK)
```json
{
  "success": true,
  "data": {
    "valid": true,
    "certificate": {
      "id": "123e4567-e89b-12d3-a456-426614174000",
      "user_email": "user@example.com",
      "course_name": "Advanced TypeScript Development",
      "description": "Corso completo su TypeScript avanzato",
      "issued_date": "2024-01-15T10:30:00.000Z",
      "revoked": false,
      "public_key_id": "rsa-2024-01",
      "metadata": {}
    },
    "verified_at": "2024-01-15T15:45:00.000Z",
    "public_key_id": "rsa-2024-01"
  },
  "message": "Certificate is valid"
}
```

#### Response per Certificato Non Valido
```json
{
  "success": true,
  "data": {
    "valid": false,
    "reason": "Certificate has been revoked: Issued in error",
    "verified_at": "2024-01-15T15:45:00.000Z",
    "public_key_id": "rsa-2024-01"
  },
  "message": "Certificate verification completed"
}
```

#### Errori
- `400 Bad Request`: ID certificato non valido (formato UUID)
- `500 Internal Server Error`: Errore durante la verifica

#### Esempio cURL
```bash
curl -X GET http://localhost:3000/certificates/123e4567-e89b-12d3-a456-426614174000/verify
```

---

### 3. Download Certificato

**GET** `/certificates/{id}/download`

Scarica il file del certificato. Richiede autenticazione e l'utente può scaricare solo i propri certificati (gli admin possono scaricare tutti).

#### Headers
```
Authorization: Bearer <jwt-token>
```

#### Parameters
| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| `id` | string (UUID) | ID del certificato da scaricare |

#### Response (200 OK)
```
Content-Type: application/pdf (o tipo originale del file)
Content-Length: <file-size>
Content-Disposition: attachment; filename="certificate-name.pdf"
Cache-Control: no-cache, no-store, must-revalidate

[Binary file data]
```

#### Errori
- `400 Bad Request`: ID certificato non valido
- `401 Unauthorized`: Token JWT mancante o non valido
- `403 Forbidden`: Permessi insufficienti per scaricare questo certificato
- `404 Not Found`: Certificato non trovato
- `500 Internal Server Error`: Errore durante il download

#### Esempio cURL
```bash
curl -X GET http://localhost:3000/certificates/123e4567-e89b-12d3-a456-426614174000/download \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -o certificate.pdf
```

---

### 4. Revoca Certificato

**POST** `/certificates/{id}/revoke`

Revoca un certificato, rendendolo non valido per future verifiche. Richiede privilegi di amministratore.

#### Headers
```
Authorization: Bearer <admin-jwt-token>
Content-Type: application/json
```

#### Parameters
| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| `id` | string (UUID) | ID del certificato da revocare |

#### Request Body
```json
{
  "reason": "Certificate issued in error - incorrect course completion date",
  "additional_details": "Student did not meet all course requirements"
}
```

| Campo | Tipo | Richiesto | Descrizione |
|-------|------|-----------|-------------|
| `reason` | string | ✅ | Motivo della revoca (10-500 caratteri) |
| `additional_details` | string | ❌ | Dettagli aggiuntivi (max 1000 caratteri) |

#### Response (200 OK)
```json
{
  "success": true,
  "data": null,
  "message": "Certificate revoked successfully"
}
```

#### Errori
- `400 Bad Request`: Dati non validi o certificato già revocato
- `401 Unauthorized`: Token JWT mancante o non valido
- `403 Forbidden`: Privilegi insufficienti (richiesto ruolo admin)
- `404 Not Found`: Certificato non trovato
- `500 Internal Server Error`: Errore durante la revoca

#### Esempio cURL
```bash
curl -X POST http://localhost:3000/certificates/123e4567-e89b-12d3-a456-426614174000/revoke \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Certificate issued in error",
    "additional_details": "Student did not complete final exam"
  }'
```

---

### 5. Lista Certificati Utente

**GET** `/certificates/user/{userId}`

Recupera la lista dei certificati di un utente specifico. Gli utenti possono vedere solo i propri certificati, gli admin possono vedere tutti.

#### Headers
```
Authorization: Bearer <jwt-token>
```

#### Parameters
| Parametro | Tipo | Descrizione |
|-----------|------|-------------|
| `userId` | string (UUID) | UUID dell'utente |

#### Response (200 OK)
```json
{
  "success": true,
  "data": [
    {
      "id": "cert-uuid-1",
      "user_uuid": "user-uuid-123",
      "user_email": "user@example.com",
      "course_name": "TypeScript Fundamentals",
      "description": "Corso base di TypeScript",
      "issued_date": "2024-01-10T10:00:00.000Z",
      "file_path": "certificates/2024/01/user-uuid/cert1.pdf",
      "original_filename": "typescript-fundamentals.pdf",
      "content_type": "application/pdf",
      "file_size": 856432,
      "public_key_id": "rsa-2024-01",
      "revoked": false,
      "revoked_at": null,
      "revoked_reason": null,
      "metadata": {},
      "created_at": "2024-01-10T10:00:00.000Z",
      "updated_at": "2024-01-10T10:00:00.000Z"
    },
    {
      "id": "cert-uuid-2",
      "user_uuid": "user-uuid-123",
      "user_email": "user@example.com",
      "course_name": "Advanced Node.js",
      "description": "Corso avanzato di Node.js",
      "issued_date": "2024-01-15T14:30:00.000Z",
      "file_path": "certificates/2024/01/user-uuid/cert2.pdf",
      "original_filename": "nodejs-advanced.pdf",
      "content_type": "application/pdf",
      "file_size": 1024768,
      "public_key_id": "rsa-2024-01",
      "revoked": false,
      "revoked_at": null,
      "revoked_reason": null,
      "metadata": {},
      "created_at": "2024-01-15T14:30:00.000Z",
      "updated_at": "2024-01-15T14:30:00.000Z"
    }
  ],
  "message": "Retrieved 2 certificate(s) for user"
}
```

#### Errori
- `400 Bad Request`: ID utente non valido o permessi insufficienti
- `401 Unauthorized`: Token JWT mancante o non valido
- `404 Not Found`: Utente non trovato
- `500 Internal Server Error`: Errore durante il recupero

#### Esempio cURL
```bash
curl -X GET http://localhost:3000/certificates/user/123e4567-e89b-12d3-a456-426614174000 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

---

## Modelli di Dati

### CertificateResponseDto
```typescript
{
  id: string;                    // UUID del certificato
  user_uuid: string;             // UUID dell'utente proprietario
  user_email: string;            // Email dell'utente (per identificazione)
  course_name: string;           // Nome del corso
  description: string | null;    // Descrizione opzionale
  issued_date: Date;             // Data di emissione
  file_path?: string;            // Percorso file (solo per utenti autorizzati)
  original_filename: string;     // Nome file originale
  content_type: string;          // Tipo MIME del file
  file_size: number;             // Dimensione file in bytes
  public_key_id: string;         // ID della chiave pubblica usata
  revoked: boolean;              // Stato di revoca
  revoked_at: Date | null;       // Data di revoca
  revoked_reason: string | null; // Motivo della revoca
  metadata: Record<string, any>; // Metadati aggiuntivi
  created_at: Date;              // Data di creazione
  updated_at: Date;              // Data ultimo aggiornamento
}
```

### VerificationResultDto
```typescript
{
  valid: boolean;                // Se il certificato è valido
  certificate?: {                // Informazioni certificato (se valido)
    id: string;
    user_email: string;
    course_name: string;
    description: string | null;
    issued_date: Date;
    revoked: boolean;
    public_key_id: string;
    metadata: Record<string, any>;
  };
  reason?: string;               // Motivo se non valido
  verified_at: Date;             // Timestamp della verifica
  public_key_id?: string;        // ID chiave usata per la verifica
}
```

---

## Codici di Errore

### Errori Specifici del Sistema di Certificazione

| Codice | Descrizione |
|--------|-------------|
| `CERTIFICATE_NOT_FOUND` | Certificato non trovato |
| `CERTIFICATE_REVOKED` | Certificato revocato |
| `INVALID_CERTIFICATE` | Formato certificato non valido |
| `SIGNATURE_VERIFICATION_FAILED` | Verifica firma fallita |
| `KEY_NOT_FOUND` | Chiave crittografica non trovata |
| `STORAGE_ERROR` | Errore di archiviazione file |
| `HASH_CALCULATION_ERROR` | Errore calcolo hash |
| `UNAUTHORIZED_ACCESS` | Accesso non autorizzato al certificato |
| `INVALID_FILE_FORMAT` | Formato file non supportato |
| `FILE_SIZE_EXCEEDED` | Dimensione file superata |

---

## Sicurezza

### Autenticazione e Autorizzazione
- **JWT Tokens**: Tutti gli endpoint protetti richiedono token JWT validi
- **Role-Based Access**: Operazioni admin richiedono ruolo `admin`
- **Ownership Validation**: Gli utenti possono accedere solo ai propri certificati

### Crittografia
- **Algoritmi Supportati**: RSA-2048, ECDSA P-256
- **Hash Function**: SHA-256 per integrità file
- **Signature Format**: Base64 encoded
- **Key Management**: Rotazione chiavi supportata con identificatori versione

### Validazione Input
- **UUID Validation**: Tutti gli ID devono essere UUID v4 validi
- **File Validation**: Controllo tipo MIME e dimensione file
- **Content Validation**: Validazione campi con class-validator

### Audit Logging
Tutte le operazioni sui certificati vengono registrate con:
- Timestamp dell'operazione
- ID utente e email
- Indirizzo IP e User Agent
- Dettagli dell'operazione
- Risultato dell'operazione

---

## Rate Limiting

| Endpoint | Limite | Finestra |
|----------|--------|----------|
| `POST /certificates` | 10 richieste | 1 minuto |
| `GET /certificates/*/verify` | 100 richieste | 1 minuto |
| `GET /certificates/*/download` | 50 richieste | 1 minuto |
| `POST /certificates/*/revoke` | 5 richieste | 1 minuto |
| `GET /certificates/user/*` | 20 richieste | 1 minuto |

---

## Esempi di Integrazione

### JavaScript/TypeScript
```typescript
// Verifica certificato
async function verifyCertificate(certificateId: string) {
  const response = await fetch(`/certificates/${certificateId}/verify`);
  const result = await response.json();
  
  if (result.success && result.data.valid) {
    console.log('Certificato valido:', result.data.certificate);
  } else {
    console.log('Certificato non valido:', result.data.reason);
  }
}

// Download certificato
async function downloadCertificate(certificateId: string, token: string) {
  const response = await fetch(`/certificates/${certificateId}/download`, {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (response.ok) {
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'certificate.pdf';
    a.click();
  }
}
```

### Python
```python
import requests

# Verifica certificato
def verify_certificate(certificate_id):
    response = requests.get(f'/certificates/{certificate_id}/verify')
    result = response.json()
    
    if result['success'] and result['data']['valid']:
        print('Certificato valido:', result['data']['certificate'])
    else:
        print('Certificato non valido:', result['data']['reason'])

# Genera certificato
def generate_certificate(user_uuid, course_name, file_path, token):
    with open(file_path, 'rb') as f:
        files = {'certificate_file': f}
        data = {
            'user_uuid': user_uuid,
            'course_name': course_name
        }
        headers = {'Authorization': f'Bearer {token}'}
        
        response = requests.post('/certificates', 
                               data=data, 
                               files=files, 
                               headers=headers)
        return response.json()
```

---

## Testing

### Test di Verifica
```bash
# Test certificato valido
curl -X GET http://localhost:3000/certificates/valid-cert-id/verify

# Test certificato inesistente
curl -X GET http://localhost:3000/certificates/00000000-0000-0000-0000-000000000000/verify

# Test ID non valido
curl -X GET http://localhost:3000/certificates/invalid-id/verify
```

### Test di Generazione
```bash
# Test generazione certificato
curl -X POST http://localhost:3000/certificates \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -F "user_uuid=123e4567-e89b-12d3-a456-426614174000" \
  -F "course_name=Test Course" \
  -F "certificate_file=@test-certificate.pdf"
```

---

## Supporto

Per supporto tecnico o domande sull'API:
- **Email**: dev@vitoesposito.it
- **Documentazione**: `/docs/certificates-api.md`
- **Repository**: Link al repository del progetto

---

## Changelog

### v1.0.0 (2024-01-15)
- Implementazione iniziale del sistema di certificazione digitale
- Supporto per generazione, verifica, download e revoca certificati
- Integrazione con MinIO per storage file
- Sistema di audit logging completo
- Supporto per chiavi RSA e ECDSA