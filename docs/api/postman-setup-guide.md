# 📮 Postman Setup Guide

## 📋 Overview

This guide will help you configure and use the Postman collection to test the **Pandom Stack** API with the new **httpOnly cookie-based authentication** system.

## 🚀 **Initial Setup**

### **1. Import the Collection**

1. Open Postman
2. Click **Import**
3. Select the `pandom-postman-collection.json` file
4. The collection will be imported with all endpoints

### **2. Configure Environment**

Create a new environment with the following variables:

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

## 🔐 **httpOnly Cookies Authentication**

### **Important: Automatic Cookie Management**

Unlike the previous Bearer token system, authentication now works with **httpOnly cookies**:

- ✅ **Automatic**: Cookies are automatically managed by Postman
- ✅ **Secure**: No need to copy/paste tokens manually
- ✅ **Transparent**: Cookies are automatically sent with every request

### **Authentication Flow**

1. **Register a user** (optional)
2. **Login** - Cookies are automatically set
3. **Use protected endpoints** - Cookies are automatically sent

## 📝 **Testing Endpoints**

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

**Note**: After login, `access_token` and `refresh_token` cookies are automatically set.

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

**Note**: Requires admin role.

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

## 🔧 **Advanced Configuration**

### **Cookie Management in Postman**

Postman automatically manages cookies, but you can view them:

1. Go to **Cookies** in the sidebar
2. Select your domain (e.g., `localhost:3000`)
3. View the set cookies:
   - `access_token`
   - `refresh_token`

### **Environment Variables**

The collection uses these variables:

- `{{base_url}}` - API base URL
- `{{user_uuid}}` - User UUID (automatically set after login)
- `{{session_id}}` - Session ID (automatically set after login)

### **Test Scripts**

Each request includes automatic tests:

```javascript
// Basic test for all requests
pm.test('Response time is less than 5000ms', function () {
    pm.expect(pm.response.responseTime).to.be.below(5000);
});

pm.test('Response has success field', function () {
    const response = pm.response.json();
    pm.expect(response).to.have.property('success');
});
```

## 🚨 **Troubleshooting**

### **Cookies not being sent**

1. Verify the URL is correct
2. Make sure the server is running
3. Check for CORS errors

### **401 Unauthorized Error**

1. Login first to set cookies
2. Verify cookies are present
3. Check if token has expired

### **403 Forbidden Error**

1. Verify you have necessary permissions
2. For admin endpoints, make sure you're logged in as admin
3. Check user role

## 📊 **Monitoring and Debug**

### **Postman Console**

Use the console to see:
- Complete HTTP requests
- Cookies sent and received
- Response headers

### **Test Results**

Each request shows:
- ✅ Status code
- ⏱️ Response time
- 📊 Test results
- 📝 Response body

## 🔄 **Recommended Workflow**

### **1. Initial Setup**
1. Import the collection
2. Configure environment
3. Start backend server

### **2. Authentication Testing**
1. Register a new user
2. Login
3. Verify cookies are set

### **3. Endpoint Testing**
1. Test public endpoints
2. Test protected endpoints
3. Test admin endpoints (if applicable)

### **4. Security Testing**
1. Test security logs
2. Test session management
3. Test GDPR data export

## 📱 **Complete Collection**

The collection includes:

- **Authentication** (9 endpoints)
- **User Profile** (2 endpoints)
- **Security** (6 endpoints)
- **Admin** (5 endpoints)
- **Resilience** (4 endpoints)

**Total**: 26 fully configured endpoints

## 🎯 **Best Practices**

1. **Always use environment** to manage variables
2. **Test in sequence** - auth first, then protected endpoints
3. **Verify cookies** after login
4. **Use automatic tests** to validate responses
5. **Keep collection updated** with API changes

---

**Pandom Stack Postman Collection** - Complete collection for testing the API with httpOnly cookie authentication.
