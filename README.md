# Image Steganography — Backend (Java / Spring Boot)

Backend service for the Image Steganography project.  
Provides powerful REST APIs to **encode** and **decode** hidden messages inside images, with optional encryption.

> **Original Python v1.0 Code:**  
> Archived under Releases in this repository.

***

## 🚀 Live Demo

- **Frontend UI** with full backend integration: [Live Demo](https://image-steganography-gpt.vercel.app/)
  - _Note: Backend is hosted on a free Render instance. Please allow ~30 seconds for cold start._

***

## 🐳 Docker

Pull the latest backend image:

```bash
docker pull prasad584/image-steganography-backend:latest
```

### Environment Setup

This project requires environment variables to run properly.  
Setup options:

- **.env file:** Create this at the project root.
- **Direct configuration:** Set variables in your IDE or runtime environment.

Run with Docker:

```bash
docker run -p 8080:8080 --env-file .env prasad584/image-steganography-backend:latest
```

***

## 🔌 REST API

**Base URL:** `/api/v1`

### Encode

> Hide a secret message inside an image.

**Endpoint:**  
`POST /api/v1/encode`

**Multipart fields:**

- `image` (file, PNG recommended)
- `message` (string, required)
- `password` (string, optional)

### Decode

> Extract the secret message from an encoded image.

**Endpoint:**  
`POST /api/v1/decode`

**Multipart fields:**

- `image` (file, encoded image)
- `password` (string, optional)

***

## 🧭 Project History

- **v1.0 (Python):**  
  Archived, available under Releases.
- **Current:**  
  Complete rewrite in **Java (Spring Boot)** — this repository serves as the backend.

***

## 👥 Contributors (v1 Team)

- [K. Anusha](https://github.com/Anusha2456)
- [P. Navanitha](https://github.com/PothugantiNavanitha)
- T. Eshwar
- [A. PremSai](https://github.com/Premsaibm)
- E. Sreeja
- [A. Sri Ram Teja](https://github.com/SriRamTejaArige)
- P. Sahruday
- G. Abhishek
- [Reddy Leela Venkata Krishna Prasad](https://gitlab.com/prasad584)

***

**Feel free to fork, contribute, and explore the power of image steganography!**