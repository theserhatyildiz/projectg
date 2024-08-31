import { UserContext } from "../../../context/UserContext";
import { useContext, useState, useEffect, } from "react";
import Footer from "../../Footer";
import { Sheet } from 'react-modal-sheet';
import ClipLoader from "react-spinners/ClipLoader";
import { useNavigate} from "react-router-dom";

export default function Account() {
    const loggedData = useContext(UserContext);
    const navigate = useNavigate();

    const [isUserNameSheetOpen, setUserNameSheetOpen] = useState(false);
    const [isEmailSheetOpen, setEmailSheetOpen] = useState(false);
    const [isDeleteSheetOpen, setDeleteSheetOpen] = useState(false);
    const [newName, setNewName] = useState('');
    const [newEmail, setNewEmail] = useState('');
    const [loading, setLoading] = useState(false); // State for loading spinner
    const [message, setMessage] = useState({ type: "invisible-msg", text: "Dummy Msg" });
    const [csrfToken, setCsrfToken] = useState(""); // State to store CSRF token
 

    async function fetchCsrfToken() {
        console.log('Fetching CSRF token...');
        try {
          const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
          const data = await response.json();
          const { csrfToken } = data;
          if (csrfToken) {
            setCsrfToken(csrfToken);
            document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
            console.log('CSRF Token stored in cookie:', csrfToken);
          }
        } catch (error) {
          console.error('Error fetching CSRF token:', error);
        }
      }

    useEffect(() => {
        fetchCsrfToken();
      }, []);

    const handleNameChange = () => {
    setLoading(true); // Show loading spinner
    fetch("http://localhost:8000/update-username", {
        method: "POST",
        body: JSON.stringify({ id: loggedData.loggedUser.userid, newName }),
        headers: {
            "Content-type": "application/json",
            "CSRF-Token": csrfToken // Include CSRF token in headers
        },
        credentials: 'include'
    })
    .then((response) => response.json())
    .then((data) => {
        setLoading(false); // Hide loading spinner
        if (data.success) {
            setMessage({ type: "success-account", text: "Kullanıcı adı güncellendi!" });
            
            // Update context or state to reflect the new username
            loggedData.setLoggedUser((prevUser) => ({ ...prevUser, name: newName }));
            
            // Update local storage
            const userData = JSON.parse(localStorage.getItem('app-user'));
            userData.name = newName;
            localStorage.setItem('app-user', JSON.stringify(userData));
            
            setTimeout(() => {
                setUserNameSheetOpen(false);
            }, 2500);
        } else {
            setMessage({ type: "error-account", text: data.message });
        }
        
        // Clear message after 2 seconds
        setTimeout(() => {
            setMessage({ type: "invisible-msg", text: "Dummy Msg" });
        }, 2500);
    })
    .catch((err) => {
        setLoading(false); // Hide loading spinner
        console.error(err);
        setMessage({ type: "error-account", text: "Kullanıcı adı güncellenemedi!" });
        
        // Clear message after 2 seconds
        setTimeout(() => {
            setMessage({ type: "invisible-msg", text: "Dummy Msg" });
        }, 3000);
    });
};
    //Email change function
    // const handleEmailChange = () => {
    //     setLoading(true); // Show loading spinner
    //     // Add your API call here for updating email
    //     setLoading(false); // Hide loading spinner after API call
    //     setMessage({ type: "success", text: "E-posta güncellendi!" });
    //     // Close email sheet and clear message after 2 seconds
    //     setTimeout(() => {
    //         setEmailSheetOpen(false);
    //         setMessage({ type: "invisible-msg", text: "Dummy Msg" });
    //     }, 2000);
    // };

    // To logout from the application

    function logout() {
        fetch('http://localhost:8000/logout', { // Ensure you have the correct URL
            method: 'POST',
            headers: {
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "CSRF-Token": csrfToken // Include CSRF token in headers
            },
            credentials: 'include'  // Include cookies in the request
        })
        .then(response => {
            if (response.ok) {
                // Clear the local storage and update logged user data
                localStorage.removeItem("app-user");
                loggedData.setLoggedUser(null);
                // Redirect to login page
                navigate("/login");
            } else {
                setMessage({ type: "error-account", text: "Çıkış yapılamadı!" });
                console.error('Failed to log out');
            }
        })
        .catch(error => {
            setMessage({ type: "error-account", text: "Çıkış yapılırken bir hata oluştu!" });
            console.error('Error during logout:', error);
        });
    }

    return (
        <section className="container account-container">
            <div className="account-list">
                <ul className="list-settings">
                    <div className="list-headings">
                        <span>Hesap</span>
                    </div>
                    <div className="list-items">
                        <li>Kullanıcı Adı</li>
                        <button onClick={() => setUserNameSheetOpen(true)}>{loggedData.loggedUser.name}</button>
                    </div>
                    <div className="list-items">
                        <li>E-posta</li>
                        <button onClick={() => setEmailSheetOpen(true)}>{loggedData.loggedUser.email}</button>
                    </div>

                    {/* Delete my account button */}
                    {/* <div className="list-items">
                        <li>
                            <button className="btn-account-delete" onClick={() => setDeleteSheetOpen(true)}>Hesabı Sil</button>
                        </li>
                    </div> */}


                    <div>
                        <button className="btn-logout" onClick={logout}>Çıkış</button>
                        {/* Add user's height information here */}
                    </div>
                </ul>
            </div>

            <Footer />

            {/* Bottom Sheet for Username */}
            <Sheet className="bottom-sheet-account" snapPoints={[180, 0]} isOpen={isUserNameSheetOpen} onClose={() => setUserNameSheetOpen(false)}>
                <Sheet.Container>
                    <Sheet.Header />
                    <Sheet.Content>
                        <div className="bottom-sheet-account-group">
                            <input 
                                type="text" 
                                value={newName} 
                                onChange={(e) => setNewName(e.target.value)} 
                                placeholder="Yeni Kullanıcı Adı" 
                                required
                            />
                            <div className="bottom-sheet-account-buttons">
                                <button className="btn" onClick={handleNameChange}>Kaydet</button>
                            </div>
                            <p className={message.type}>{message.text}</p>
                             {/* Display loading spinner */}
                             {loading && (
                                    <div className="spinner-container-account">
                                        <ClipLoader
                                            color="#d73750"
                                            loading={loading}
                                            size={25}
                                            aria-label="Loading Spinner"
                                            data-testid="loader"
                                        />
                                    </div>
                                )}
                        </div>
                    </Sheet.Content>
                </Sheet.Container>
                <Sheet.Backdrop />
            </Sheet>

            {/* Bottom Sheet for Email */}
            {/* <Sheet className="bottom-sheet-account" snapPoints={[150, 0]} isOpen={isEmailSheetOpen} onClose={() => setEmailSheetOpen(false)}>
                <Sheet.Container>
                    <Sheet.Header />
                    <Sheet.Content>
                        <div className="bottom-sheet-account-group">
                            <input 
                                type="email" 
                                value={newEmail} 
                                onChange={(e) => setNewEmail(e.target.value)} 
                                placeholder="Yeni e-posta" 
                                required
                            />
                            <div className="bottom-sheet-account-buttons">
                                <button className="btn" onClick={handleEmailChange}>Kaydet</button>
                            </div>
                        </div>
                    </Sheet.Content>
                </Sheet.Container>
                <Sheet.Backdrop />
            </Sheet> */}

            {/* Bottom Sheet for Deleting Account */}
            {/* <Sheet snapPoints={[200, 0]} isOpen={isDeleteSheetOpen} onClose={() => setDeleteSheetOpen(false)}>
                <Sheet.Container>
                    <Sheet.Header />
                    <Sheet.Content>
                        <div style={{ padding: '16px' }}>
                            <h2>Hesabı Sil</h2>
                            <p>Hesabınızı silmek istediğinizden emin misiniz?</p>
                            <button onClick={() => {
                                // Add functionality to delete the account here
                                setDeleteSheetOpen(false);
                            }}>
                                Evet, Sil
                            </button>
                            <button onClick={() => setDeleteSheetOpen(false)}>Hayır, İptal Et</button>
                        </div>
                    </Sheet.Content>
                </Sheet.Container>
                <Sheet.Backdrop />
            </Sheet> */}

        </section>
    );
}