// context/UserContext.jsx
import { createContext, useState } from 'react';

export const UserContext = createContext();

export function UserProvider({ children }) {
    const [loggedUser, setLoggedUser] = useState(null);
    const [currentDateView, setCurrentDateView] = useState(new Date());

    return (
        <UserContext.Provider value={{ loggedUser, setLoggedUser, currentDateView, setCurrentDateView }}>
            {children}
        </UserContext.Provider>
    );
}
