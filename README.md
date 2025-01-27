# API Documentation

## Base URL
`https://houzez-server.vercel.app/api`

---

## **Authentication**

### **Login**
- **POST** `/auth/login`
  - **Description**: Logs in a user and returns a JWT token.
  - **Request Body**:
    ```json
    {
      "email": "user@example.com",
      "password": "password123"
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "token": "<JWT_TOKEN>"
    }
    ```

### **Verify Token**
- **GET** `/auth/verify`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Verifies the validity of a JWT token.
  - **Response**:
    ```json
    {
      "success": true,
      "user": {
        "email": "user@example.com",
        "role": "admin"
      }
    }
    ```

---

## **Users**

### **Get All Users**
- **GET** `/users`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Retrieves a list of all users (Admin only).
  - **Response**:
    ```json
    [
      {
        "_id": "12345",
        "email": "user@example.com",
        "role": "agent"
      }
    ]
    ```

### **Get User by Email**
- **GET** `/users/:email`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Fetches user details by email.
  - **Response**:
    ```json
    {
      "_id": "12345",
      "email": "user@example.com",
      "role": "user"
    }
    ```

### **Update User Role**
- **PATCH** `/users/:email`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Updates the role of a user (Admin only).
  - **Request Body**:
    ```json
    {
      "role": "agent"
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "User role updated"
    }
    ```

---

## **Properties**

### **Get All Properties**
- **GET** `/properties`
  - **Description**: Retrieves a list of all properties.
  - **Response**:
    ```json
    [
      {
        "_id": "12345",
        "title": "Luxury Apartment",
        "location": "Downtown",
        "price": 500000
      }
    ]
    ```

### **Get Property by ID**
- **GET** `/properties/:id`
  - **Description**: Fetches details of a specific property by ID.
  - **Response**:
    ```json
    {
      "_id": "12345",
      "title": "Luxury Apartment",
      "location": "Downtown",
      "price": 500000,
      "description": "A beautiful apartment in the city center."
    }
    ```

### **Add a Property**
- **POST** `/properties`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Adds a new property (Agent only).
  - **Request Body**:
    ```json
    {
      "title": "Luxury Apartment",
      "location": "Downtown",
      "price": 500000,
      "description": "A beautiful apartment in the city center."
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Property added successfully"
    }
    ```

### **Update Property**
- **PATCH** `/properties/:id`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Updates details of an existing property (Agent only).
  - **Request Body**:
    ```json
    {
      "price": 550000
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Property updated successfully"
    }
    ```

### **Delete Property**
- **DELETE** `/properties/:id`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Deletes a property (Admin or Agent).
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Property deleted"
    }
    ```

---

## **Reviews**

### **Get Reviews for a Property**
- **GET** `/reviews/:propertyId`
  - **Description**: Retrieves all reviews for a specific property.
  - **Response**:
    ```json
    [
      {
        "_id": "67890",
        "userEmail": "reviewer@example.com",
        "rating": 4,
        "comment": "Great property!"
      }
    ]
    ```

### **Add a Review**
- **POST** `/reviews`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Adds a new review for a property.
  - **Request Body**:
    ```json
    {
      "propertyId": "12345",
      "rating": 5,
      "comment": "Amazing property!"
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Review added"
    }
    ```

---

## **Offers**

### **Make an Offer**
- **POST** `/offers`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Submits an offer for a property.
  - **Request Body**:
    ```json
    {
      "propertyId": "12345",
      "offerPrice": 480000
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Offer submitted"
    }
    ```

### **Accept or Reject Offer**
- **PATCH** `/offers/:id`
  - **Headers**:
    ```
    Authorization: Bearer <JWT_TOKEN>
    ```
  - **Description**: Accepts or rejects an offer (Admin or Agent).
  - **Request Body**:
    ```json
    {
      "status": "accepted"
    }
    ```
  - **Response**:
    ```json
    {
      "success": true,
      "message": "Offer updated"
    }
    
