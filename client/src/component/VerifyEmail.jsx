import React, { useState, useEffect } from 'react';
import { useParams, Link } from 'react-router-dom';

export default function VerifyEmail() {
    const { id, token } = useParams();
    const [message, setMessage] = useState('');
    const [verified, setVerified] = useState(false);
    const [csrfToken, setCsrfToken] = useState(""); // State to store CSRF token

    useEffect(() => {
        fetchCsrfToken(); // Fetch CSRF token on component mount
    }, []);

    async function fetchCsrfToken() {
        try {
            const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
            const { csrfToken } = await response.json();
            // console.log('CSRF Token fetched:', csrfToken);
            if (csrfToken) {
                setCsrfToken(csrfToken);
                document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; HttpOnly; SameSite=Strict; path=/`;
                // console.log('CSRF Token stored in cookie:',csrfToken );
                verifyEmail(csrfToken); // Proceed to verify email after fetching CSRF token
            }
        } catch (error) {
            // console.error('Error fetching CSRF token:', error);
            setMessage('E-posta doğrulama işlemi başarısız oldu.');
        }
    }

    async function verifyEmail(csrfToken) {
        try {
            // console.log('XSRF-TOKEN cookie:', csrfToken); // Log CSRF token from cookie
            const response = await fetch(`http://localhost:8000/verify/${id}/${token}`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "CSRF-Token": csrfToken // Include CSRF token in headers
                },
                credentials: 'include',
            });

            if (response.ok) {
                setMessage('Teşekkürler! E-posta adresiniz başarıyla doğrulandı!');
                setVerified(true);
            } else {
                setMessage('E-posta doğrulama işlemi başarısız oldu.');
            }
        } catch (err) {
            setMessage('E-posta doğrulama işlemi başarısız oldu.');
        }
    }

    return (
        <section className="container verify-msg-container">
            {message && (
                <div className='verify-msg'>
                    <h2>{message}</h2>
                    {verified && (
                        <>
                            <h2>Hesabınız artık aktif.</h2>
                            <button className="btn"><Link to="/login">Hesabınıza Giriş Yapın</Link></button>
                        </>
                    )}
                </div>
            )}
        </section>
    );
}