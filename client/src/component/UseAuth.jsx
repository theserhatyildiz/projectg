import { useEffect, useState } from 'react';
import { jwtDecode } from "jwt-decode";

export function useAuth() {
  const [loggedUser, setLoggedUser] = useState(() => {
    const storedUser = localStorage.getItem("app-user");
    if (storedUser) {
      try {
        console.log("Loaded user from localStorage:", storedUser);
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
      console.log("Fetching CSRF token...");
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
      console.log("Refreshing access token...");
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
        console.log("Access token refreshed successfully:", data.token);
        if (data.token) {
          const updatedUser = { ...parsedUser, token: data.token };
          localStorage.setItem("app-user", JSON.stringify(updatedUser));
          setLoggedUser(updatedUser);
          return data.token;  // Return the new token
        }
      } else {
        console.error('Failed to refresh access token:', response.statusText);
        if (response.status === 403) {
          // If the server returns a 403 status, log out the user
          console.log("Access forbidden, logging out user.");
          setLoggedUser(null);
          localStorage.removeItem("app-user");
        }
      }
    } catch (error) {
      console.error('Error refreshing access token:', error);
      if (retries > 0) {
        console.log(`Retrying to refresh access token. Attempts left: ${retries - 1}`);
        setTimeout(() => refreshAccessToken(parsedUser, retries - 1), 2000); // Retry with exponential backoff
      } else {
        console.log("Failed to refresh token after retries, logging out.");
        setLoggedUser(null);
        localStorage.removeItem("app-user");
      }
    }
  }

  // Function to fetch data with token handling
  async function fetchData(url) {
    const storedUser = localStorage.getItem("app-user");
    let parsedUser;

    if (storedUser) {
      parsedUser = JSON.parse(storedUser);
      const accessToken = parsedUser?.token;
      console.log("Fetched stored user data:", parsedUser);

      if (accessToken) {
        const now = Math.floor(Date.now() / 1000);
        const { exp: accessTokenExp } = jwtDecode(accessToken);
        console.log(`Access token expires at: ${accessTokenExp}, current time: ${now}`);

        if (now >= accessTokenExp) {
          console.log("Access token expired, refreshing...");
          const newToken = await refreshAccessToken(parsedUser);
          if (!newToken) return;  // Stop if the refresh failed
          parsedUser.token = newToken;
        }
      }
    }

    // Now fetch the data using the valid token
    console.log("Fetching data from URL:", url);
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
        console.log("Received 401, refreshing token...");
        await refreshAccessToken(parsedUser);
        return fetchData(url); // Retry after refreshing the token
      }
    }

    const data = await response.json();
    console.log("Data fetched successfully:", data);
    return data;
  }

  // Fetch CSRF token on initial mount
  useEffect(() => {
    fetchCsrfToken();
  }, []);

  // Check and refresh tokens periodically
  useEffect(() => {
    const interval = setInterval(async () => {
      console.log("Periodic token check...");
      const storedUser = localStorage.getItem("app-user");
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        const accessToken = parsedUser?.token;

        if (accessToken) {
          const now = Math.floor(Date.now() / 1000);
          const { exp: accessTokenExp } = jwtDecode(accessToken);
          const accessTokenMinutesLeft = (accessTokenExp - now) / 60;
          console.log(`Access token minutes left: ${accessTokenMinutesLeft}`);

          if (accessTokenMinutesLeft <= 5) { // If the access token is about to expire in the next minute
            console.log("Access token about to expire, refreshing...");
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
      console.log("Checking session status...");
      const storedUser = localStorage.getItem("app-user");
      if (storedUser) {
        const parsedUser = JSON.parse(storedUser);
        const accessToken = parsedUser?.token;

        if (accessToken) {
          const now = Math.floor(Date.now() / 1000);
          const { exp: accessTokenExp } = jwtDecode(accessToken);
          console.log(`Checking token expiry: now=${now}, exp=${accessTokenExp}`);

          if (now >= accessTokenExp) {
            // Token has expired, refresh it
            console.log("Token expired, refreshing...");
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
        console.log("App is active again, checking session status...");
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