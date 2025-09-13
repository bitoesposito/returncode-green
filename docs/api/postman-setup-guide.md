# 📮 Postman Setup Guide

## 📋 Panoramica

Questa guida ti aiuterà a configurare e utilizzare la collezione Postman per testare l'API di **Pandom Stack** con il nuovo sistema di autenticazione basato su **httpOnly cookies**.

## 🚀 **Setup Iniziale**

### **1. Importa la Collezione**

1. Apri Postman
2. Clicca su **Import**
3. Seleziona il file `pandom-postman-collection.json`
4. La collezione verrà importata con tutti gli endpoint

### **2. Configura l'Environment**

Crea un nuovo environment con le seguenti variabili:

```json
{
  "name": "Pandom Stack Local",
  "values": [
    {
      "key": "base_url",
      "value": "http://localhost:3000",
      "enabled": true
    },
    {
      "key": "user_uuid",
      "value": "",
      "enabled": true
    },
    {
      "key": "session_id",
      "value": "",
      "enabled": true
    }
  ]
}
```

## 🔐 **Autenticazione con httpOnly Cookies**

### **Importante: Gestione Automatica Cookie**

A differenza del sistema precedente con Bearer token, ora l'autenticazione funziona con **httpOnly cookies**:

- ✅ **Automatico**: I cookie vengono gestiti automaticamente da Postman
- ✅ **Sicuro**: Non devi copiare/incollare token manualmente
- ✅ **Trasparente**: I cookie vengono inviati automaticamente con ogni richiesta

### **Flusso di Autenticazione**

1. **Registra un utente** (opzionale)
2. **Fai login** - I cookie vengono impostati automaticamente
3. **Usa gli endpoint protetti** - I cookie vengono inviati automaticamente

## 📝 **Test degli Endpoint**

### **1. Authentication Endpoints**

#### **Register User**
```http
POST {{base_url}}/auth/register
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "SecurePass123!",
  "confirmPassword": "SecurePass123!"
}
```

#### **Login User**
```http
POST {{base_url}}/auth/login
Content-Type: application/json

{
  "email": "test@example.com",
  "password": "SecurePass123!",
  "rememberMe": false
}
```

**Nota**: Dopo il login, i cookie `access_token` e `refresh_token` vengono impostati automaticamente.

### **2. User Profile Endpoints**

#### **Get Profile**
```http
GET {{base_url}}/profile
```

#### **Update Profile**
```http
PUT {{base_url}}/profile
Content-Type: application/json

{
  "tags": ["developer", "fullstack"],
  "metadata": {
    "preferences": {
      "theme": "dark",
      "language": "en"
    }
  }
}
```

### **3. Security Endpoints**

#### **Get Security Logs**
```http
GET {{base_url}}/security/logs?page=1&limit=10
```

#### **Get Active Sessions**
```http
GET {{base_url}}/security/sessions
```

#### **Download User Data (GDPR)**
```http
GET {{base_url}}/security/download-data
```

### **4. Admin Endpoints**

**Nota**: Richiedono ruolo admin.

#### **Get Users**
```http
GET {{base_url}}/admin/users?page=1&limit=10
```

#### **Get System Metrics**
```http
GET {{base_url}}/admin/metrics
```

### **5. Resilience Endpoints**

#### **Get System Status**
```http
GET {{base_url}}/resilience/status
```

#### **Create Backup**
```http
POST {{base_url}}/resilience/backup
```

## 🔧 **Configurazione Avanzata**

### **Cookie Management in Postman**

Postman gestisce automaticamente i cookie, ma puoi visualizzarli:

1. Vai su **Cookies** nella barra laterale
2. Seleziona il tuo dominio (es. `localhost:3000`)
3. Visualizza i cookie impostati:
   - `access_token`
   - `refresh_token`

### **Environment Variables**

La collezione utilizza queste variabili:

- `{{base_url}}` - URL base dell'API
- `{{user_uuid}}` - UUID dell'utente (impostato automaticamente dopo login)
- `{{session_id}}` - ID della sessione (impostato automaticamente dopo login)

### **Test Scripts**

Ogni richiesta include test automatici:

```javascript
// Test di base per tutte le richieste
pm.test('Response time is less than 5000ms', function () {
    pm.expect(pm.response.responseTime).to.be.below(5000);
});

pm.test('Response has success field', function () {
    const response = pm.response.json();
    pm.expect(response).to.have.property('success');
});
```

## 🚨 **Risoluzione Problemi**

### **Cookie non vengono inviati**

1. Verifica che l'URL sia corretto
2. Assicurati che il server sia in esecuzione
3. Controlla che non ci siano errori CORS

### **Errore 401 Unauthorized**

1. Fai prima il login per impostare i cookie
2. Verifica che i cookie siano presenti
3. Controlla che il token non sia scaduto

### **Errore 403 Forbidden**

1. Verifica di avere i permessi necessari
2. Per endpoint admin, assicurati di essere loggato come admin
3. Controlla il ruolo dell'utente

## 📊 **Monitoraggio e Debug**

### **Console di Postman**

Usa la console per vedere:
- Richieste HTTP complete
- Cookie inviati e ricevuti
- Headers di risposta

### **Test Results**

Ogni richiesta mostra:
- ✅ Status code
- ⏱️ Response time
- 📊 Test results
- 📝 Response body

## 🔄 **Workflow Consigliato**

### **1. Setup Iniziale**
1. Importa la collezione
2. Configura l'environment
3. Avvia il server backend

### **2. Test di Autenticazione**
1. Registra un nuovo utente
2. Fai login
3. Verifica che i cookie siano impostati

### **3. Test degli Endpoint**
1. Testa gli endpoint pubblici
2. Testa gli endpoint protetti
3. Testa gli endpoint admin (se applicabile)

### **4. Test di Sicurezza**
1. Testa i log di sicurezza
2. Testa la gestione sessioni
3. Testa l'export dati GDPR

## 📱 **Collezione Completa**

La collezione include:

- **Authentication** (9 endpoint)
- **User Profile** (2 endpoint)
- **Security** (6 endpoint)
- **Admin** (5 endpoint)
- **Resilience** (4 endpoint)

**Totale**: 26 endpoint completamente configurati

## 🎯 **Best Practices**

1. **Usa sempre l'environment** per gestire le variabili
2. **Testa in sequenza** - prima auth, poi endpoint protetti
3. **Verifica i cookie** dopo il login
4. **Usa i test automatici** per validare le risposte
5. **Mantieni aggiornata** la collezione con le modifiche API

---

**Pandom Stack Postman Collection** - Collezione completa per testare l'API con autenticazione httpOnly cookies.