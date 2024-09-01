import { useEffect, useState } from 'react';
import { jwtDecode } from "jwt-decode";

export function useAuth() {
  const [loggedUser, setLoggedUser] = useState(() => {
    const storedUser = localStorage.getItem("app-user");
    if (storedUser) {
      try {
        return JSON.parse(storedUser);
      } catch (error) {
        console.error("Invalid user data in localStorage:", error);
        return null;
      }
    }
    return null;
  });

  const [csrfToken, setCsrfToken] = useState(""); // State to store CSRF token

  // Function to fetch CSRF token
  async function fetchCsrfToken() {
    try {
      const response = await fetch("https://galwinapp-c654a544b729.herokuapp.com/csrf-token", { credentials: 'include' });
      if (response.ok) {
        const { csrfToken } = await response.json();
        console.log('CSRF Token fetched:', csrfToken);
        if (csrfToken) {
          setCsrfToken(csrfToken);
          document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
          console.log('CSRF Token stored in cookie:', csrfToken);
        }
      } else {
        console.error('Failed to fetch CSRF token:', response.statusText);
      }
    } catch (error) {
      console.error('Error fetching CSRF token:', error);
    }
  }

  // Function to refresh the access token
  async function refreshAccessToken(parsedUser, retries = 3) {
    try {
      const response = await fetch('https://galwinapp-c654a544b729.herokuapp.com/refresh-token', {
        method: 'POST',
        headers: {
          "Content-Type": "application/json",
          "csrf-token": csrfToken
        },
        credentials: 'include',
        body: JSON.stringify({ userId: parsedUser.userid }) // Send userId in the request body
      });

      if (response.ok) {
        const data = await response.json();
        if (data.token) {
          const updatedUser = { ...parsedUser, token: data.token };
          localStorage.setItem("app-user", JSON.stringify(updatedUser));
          setLoggedUser(updatedUser);
        }
      } else {
        console.error('Failed to refresh access token:', response.statusText);
        if (response.status === 403) {
          // If the server returns a 403 status, log out the user
          setLoggedUser(null);
          localStorage.removeItem("app-user");
        }
      }
    } catch (error) {
      console.error('Error refreshing access token:', error);
      if (retries > 0) {
        setTimeout(() => refreshAccessToken(parsedUser, retries - 1), 2000); // Retry with exponential backoff
      } else {
        setLoggedUser(null);
        localStorage.removeItem("app-user");
      }
    }
  }

  // Function to fetch data with token handling
  async function fetchData(url) {
    const storedUser = localStorage.getItem("app-user");
    if (storedUser) {
      const parsedUser = JSON.parse(storedUser);
      const accessToken = parsedUser?.token;

      if (accessToken) {
        const now = Math.floor(Date.now() / 1000);
        const { exp: accessTokenExp } = jwtDecode(accessToken);

        if (now >= accessTokenExp) {
          // Token has expired, refresh it
          await refreshAccessToken(parsedUser);
        }
      }
    }

    // Now fetch the data using the valid token
    const response = await fetch(url, {
      headers: {
        Authorization: `Bearer ${parsedUser?.token}`,
        "Content-Type": "application/json"
      },
      credentials: 'include'
    });

    if (!response.ok) {
      console.error('Failed to fetch data:', response.statusText);
      if (response.status === 401) {
        // Token is invalid, try refreshing it again
        await refreshAccessToken(parsedUser);
        return fetchData(url); // Retry after refreshing the token
      }
    }

    return response.json();
  }

  // Fetch CSRF token on initial mount
  useEffect(() => {
    fetchCsrfToken();
  }, []);

  // Check and refresh tokens periodically
  useEffect(() => {
    const interval = setInterval(async () => {
      const storedUser = localStorage.getItem("app-user");
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        const accessToken = parsedUser?.token;

        if (accessToken) {
          const now = Math.floor(Date.now() / 1000);
          const { exp: accessTokenExp } = jwtDecode(accessToken);
          const accessTokenMinutesLeft = (accessTokenExp - now) / 60;

          if (accessTokenMinutesLeft <= 1) { // If the access token is about to expire in the next minute
            await refreshAccessToken(parsedUser);
          }
        }
      }
    }, 60 * 1000); // Check every minute

    return () => clearInterval(interval);
  }, [csrfToken]);

  // Add the session status check after inactivity
  useEffect(() => {
    // Function to check session status
    async function checkSessionStatus() {
      const storedUser = localStorage.getItem("app-user");
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        const accessToken = parsedUser?.token;

        if (accessToken) {
          const now = Math.floor(Date.now() / 1000);
          const { exp: accessTokenExp } = jwtDecode(accessToken);

          if (now >= accessTokenExp) {
            // Token has expired, refresh it
            await refreshAccessToken(parsedUser);
          } else {
            // Token is still valid, proceed with normal operation
            console.log("Token is still valid, continuing...");
          }
        }
      }
    }

    // Event listener for visibility change
    function handleVisibilityChange() {
      if (document.visibilityState === 'visible') {
        // The app is active again, check the session status
        checkSessionStatus();
      }
    }

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [csrfToken]);

  return { loggedUser, setLoggedUser, csrfToken, fetchData }; // Expose fetchData function
}