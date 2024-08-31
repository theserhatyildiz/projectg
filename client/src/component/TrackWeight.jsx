import { UserContext } from "../context/UserContext";
import { useContext, useState, useEffect } from "react";
import '@fortawesome/fontawesome-free/css/all.css';
import Header from "./Header";
import Footer from "./Footer";
import ClipLoader from "react-spinners/ClipLoader";

export default function TrackWeight() {
    const loggedData = useContext(UserContext);
    const [weightDetails, setWeightDetails] = useState({ weight: "", date: new Date().toISOString().slice(0, 10) });
    const [message, setMessage] = useState({ type: "", text: "" });
    const [weightEntries, setWeightEntries] = useState([]);
    const [shouldFetchData, setShouldFetchData] = useState(true);
    const [wcDetails, setWcDetails] = useState({ choice: "yes" });

    const [startDate, setStartDate] = useState(""); // State variable for the start date
    const [startDateEntry, setStartDateEntry] = useState("");

    const [loading, setLoading] = useState(true); // Initial loading state set to true
    const [color] = useState("#d73750"); // Color state for ClipLoader
    const [csrfToken, setCsrfToken] = useState(""); // State to store CSRF token

    // Define state variables to store the weekly averages and their difference
    const [weeklyAverage, setWeeklyAverage] = useState(0); // State variable for current week's average
    const [previousWeeklyAverage, setPreviousWeeklyAverage] = useState(0); // State variable for previous week's average
    const [weeklyAverageDifference, setWeeklyAverageDifference] = useState(0);
    const [totalDifference, setTotalDifference] = useState(0);

    useEffect(() => {
        fetchStartDateFromServer();
        setLoading(true); // Start loading

      if (shouldFetchData) {
        fetchWeightEntries();
        console.log("Fetching weight entries...");
      }
      setShouldFetchData(false);
    }, [shouldFetchData]);

   
    useEffect(() => {
    const fetchData = async () => {
        try {
            calculateWeeklyAverage();
            calculatePreviousWeeklyAverage();
            calculateTotalDifference();
            setLoading(false); // Stop loading after data is fetched
        } catch (error) {
            console.error("Error fetching start date from server:", error);
            setLoading(false); // Stop loading after data is fetched
        }
    };

    // Call fetchData when the component mounts
    fetchData();
}, []);

    useEffect(() => {
        async function fetchCsrfToken() {
            try {
                const response = await fetch("http://localhost:8000/csrf-token", { credentials: 'include' });
                const { csrfToken } = await response.json();
                console.log('CSRF Token fetched:', csrfToken);
                if (csrfToken) {
                    setCsrfToken(csrfToken);
                    document.cookie = `XSRF-TOKEN=${csrfToken}; Secure; SameSite=Strict; path=/`;
                    console.log('CSRF Token stored in cookie:', csrfToken);
                }
            } catch (error) {
                console.error('Error fetching CSRF token:', error);
            }
        }

        fetchCsrfToken();
    }, []);
    
    const fetchWeightEntries = () => {
        const year = new Date().getFullYear();
        const userId = loggedData.loggedUser.userid;
        const token = loggedData.loggedUser.token;
        const choice = wcDetails.choice; // Get the latest value of choice from state
    
        // Array to store all the fetched weight entries
        let allWeightEntries = [];
    
        // Function to fetch weight entries for a specific month
        const fetchEntriesForMonth = async (month, choice) => { // Pass choice as an argument
            try {
                const response = await fetch(`http://localhost:8000/weights/${userId}/${year}/${month}?choice=${choice}`, { // Include choice in the URL
                    method: "GET",
                    headers: {
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json",
                        "CSRF-Token": csrfToken // Include CSRF token in headers
                    },
                    credentials: 'include'
                });
    
                if (!response.ok) {
                    throw new Error("Failed to fetch weight entries");
                }
    
                const data = await response.json();
                return data;
            } catch (error) {
                console.error("Error fetching weight entries:", error);
                return [];
            }
        };
    
        // Array to store promises for each month's data fetch
        const promises = [];
    
        // Loop through each month of the year and fetch data
        for (let month = 1; month <= 12; month++) {
            promises.push(fetchEntriesForMonth(month, choice)); // Pass choice to fetchEntriesForMonth
        }
    
        // Resolve all promises
        Promise.all(promises)
            .then((results) => {
                // Concatenate all results into a single array
                allWeightEntries = results.reduce((acc, curr) => acc.concat(curr), []);
                console.log("All Weight Entries Data:", allWeightEntries);
                setWeightEntries(allWeightEntries);
                setLoading(false); // Stop loading after data is fetched
            })
            .catch((error) => {
                console.error("Error fetching weight entries:", error);
                setLoading(false); // Stop loading after data is fetched
            });
    };
    

    const handleInput = (event) => {
        const { name, value } = event.target;
        setWeightDetails((prevState) => ({
            ...prevState,
            [name]: value,
        }));
    }

    const handleWcInput = (event) => {
        const { name, value } = event.target;
        console.log("Choice Value:", value); // Add this line for debugging
        setWcDetails((prevState) => ({
            ...prevState,
            [name]: value,
        }));
    };


    const handleSubmit = (event) => {
        event.preventDefault();

        const formData = {
            weight: weightDetails.weight,
            date: weightDetails.date,
            choice: wcDetails.choice
        };

        console.log("handle submit Choice Value:", formData.choice); // Add this logging statement
        console.log("handle submit formData Value:", formData); // Add this logging statement


        const existingEntry = weightEntries.find(entry => entry.date === weightDetails.date);

        if (existingEntry) {
            updateWeightEntry(existingEntry._id);
        } else {
            createWeightEntry(formData);
        }
    }

    const createWeightEntry = (formData) => {
        fetch("http://localhost:8000/weights", {
            method: "POST",
            body: JSON.stringify(formData),
            headers: {
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "Content-Type": "application/json",
                "CSRF-Token": csrfToken // Include CSRF token in headers
            },
            credentials: 'include'
        })
        .then(response => {
            console.log("Response object:", response); // Log the entire response object
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            console.log("Response data:", data); // Log the response data
            setMessage({ type: "success", text: "Başarılı ✅" });
            fetchWeightEntries();
        })
        .catch(error => {
            console.error("Fetch error:", error); // Log any errors
            setMessage({ type: "error", text: "Bir hata oluştu!" });
        })
        .finally(() => {
            setTimeout(() => {
                setMessage({ type: "", text: "" });
            }, 2000);
        });
    }


    const handleDateChange = (event) => {
        setWeightDetails((prevState) => ({
            ...prevState,
            date: event.target.value
        }));
    }


    const handleDelete = (entryId) => {
        fetch(`http://localhost:8000/weights/${entryId}`, {
            method: "DELETE",
            headers: {
                "Authorization": `Bearer ${loggedData.loggedUser.token}`,
                "CSRF-Token": csrfToken // Include CSRF token in headers
            },
            credentials: 'include'
        })
        .then(response => {
            if (response.status === 200) {
                // Refresh weight entries after deletion
                fetchWeightEntries();
            } else {
                setMessage({ type: "error", text: "Bir hata oluştu!" });
                setTimeout(() => {
                    setMessage({ type: "", text: "" });
                }, 2000);
            }
        })
        .catch(err => {
            console.log(err);
        });
    }
    
    // Group weight entries by month
    const groupWeightEntriesByMonth = () => {
        const groupedEntries = {};

        weightEntries.forEach((entry) => {
            const monthYear = new Date(entry.date).toLocaleString('tr-TR', { month: 'long', year: 'numeric' });
            if (!groupedEntries[monthYear]) {
                groupedEntries[monthYear] = [];
            }
            groupedEntries[monthYear].push(entry);
        });

        // Sort entries within each month
        Object.values(groupedEntries).forEach((entries) => {
            entries.sort((a, b) => new Date(b.date) - new Date(a.date));
        });

        // Reverse the order of months
        return Object.entries(groupedEntries).reverse();
    };

        ////// Weekly Avarage = Guncel Ortlama //////
        
        const calculateWeeklyAverage = () => {
            let effectiveStartDate = startDate; // Initialize effectiveStartDate with startDate
        
            // If startDate is null or empty, set it to the date of the first entry
            if (!startDate && weightEntries.length > 0) {
                effectiveStartDate = weightEntries[0].date;
            }
        
            // If effectiveStartDate is still null or empty, set weekly average to 0 and return
            if (!effectiveStartDate) {
                setWeeklyAverage(0);
                return;
            }
        
            // Get the last 7 entries
            const lastSevenEntries = weightEntries
                .slice()
                .reverse()
                .filter((entry) => new Date(entry.date) >= new Date(effectiveStartDate))
                .slice(0, 7);
        
            // Calculate the average if there are entries within the last 7 days
            if (lastSevenEntries.length > 0) {
                const sum = lastSevenEntries.reduce((total, entry) => total + parseFloat(entry.weight), 0);
                const average = sum / lastSevenEntries.length;
                setWeeklyAverage(average.toFixed(1));
            } else {
                setWeeklyAverage(0); // If no entries in the last 7 days, set average to 0
            }
        };

        ////// Previous Weekly Avarage = Onceki Ortlama //////
        
        const calculatePreviousWeeklyAverage = () => {
            let effectiveStartDate = startDate; // Initialize effectiveStartDate with startDate
        
            // If startDate is null or empty, set it to the date of the first entry
            if (!startDate && weightEntries.length > 0) {
                effectiveStartDate = weightEntries[0].date;
            }
        
            // If effectiveStartDate is still null or empty, set previous weekly average to 0 and return
            if (!effectiveStartDate) {
                setPreviousWeeklyAverage(0);
                return;
            }
        
            // Get the entries from days 8 to 14
            const previousWeekEntries = weightEntries
                .slice()
                .reverse()
                .filter((entry) => new Date(entry.date) >= new Date(effectiveStartDate))
                .slice(7, 14);
        
            // Calculate the average if there are entries from days 8 to 14
            if (previousWeekEntries.length > 0) {
                const sum = previousWeekEntries.reduce((total, entry) => total + parseFloat(entry.weight), 0);
                const average = sum / previousWeekEntries.length;
                setPreviousWeeklyAverage(average.toFixed(1));
            } else {
                setPreviousWeeklyAverage(0); // If no entries from days 8 to 14, set average to 0
            }
        };
        
    
        ////// WeeklyAverageChange = Haftalik Degisim //////

        const calculateWeeklyAverageDifference = () => {
            let difference = 0;
            if (previousWeeklyAverage !== 0) {
                difference = parseFloat(weeklyAverage) - parseFloat(previousWeeklyAverage);
            }
            setWeeklyAverageDifference(difference.toFixed(1));
        };
        

        ////// Total Change = Toplam Degisim //////

        const calculateTotalDifference = () => {
            // Sort weightEntries array based on the 'date' property
            weightEntries.sort((a, b) => new Date(a.date) - new Date(b.date));
        
            if (weightEntries.length > 1) {
                let startIndex = 0;
                if (startDate) {
                    // Find the index of the first entry after or on the start date
                    startIndex = weightEntries.findIndex(entry => new Date(entry.date) >= new Date(startDate));
                    if (startIndex === -1) {
                        // If no entry is found after the start date, consider the last entry
                        startIndex = weightEntries.length - 1;
                    }
                }
                const firstWeight = parseFloat(weightEntries[startIndex].weight);
                const lastWeight = parseFloat(weightEntries[weightEntries.length - 1].weight);
                const difference = lastWeight - firstWeight;
                setTotalDifference(difference.toFixed(1));
        
                // Get the date of the last entry
                const lastEntryDate = new Date(weightEntries[weightEntries.length - 1].date);
                console.log("Date of last entry:", lastEntryDate);
                
                const firstEntry = weightEntries[startIndex];
                console.log("First entry:", firstEntry);
            } else {
                setTotalDifference(0);
            }
        };
        
        

        // Invoke the calculation functions when weightEntries or startDate change
        useEffect(() => {
            calculateWeeklyAverage();
            calculatePreviousWeeklyAverage();
            calculateTotalDifference();
        }, [weightEntries, startDate]);

        // Calculate the difference whenever either of the averages change
        useEffect(() => {
            calculateWeeklyAverageDifference();
        }, [weeklyAverage, previousWeeklyAverage]);

        // Ensure that the calculations for total difference depend on both weekly averages
        useEffect(() => {
            calculateTotalDifference();
        }, [weeklyAverage, previousWeeklyAverage]);

            

    ///// Kilo Girisi Box Logic /////
        
        // Define state variable to store whether the entry field should be shown or hidden
    const [showEntryField, setShowEntryField] = useState(true);

    // Function to toggle the visibility of the entry field and update local storage
    const handleEntryClick = () => {
        setShowEntryField(!showEntryField);
        // Update local storage
        localStorage.setItem('showEntryField', JSON.stringify(!showEntryField));
    };

    // useEffect to read from local storage and set initial value of showEntryField
    useEffect(() => {
        const storedShowEntryField = JSON.parse(localStorage.getItem('showEntryField'));
        if (storedShowEntryField !== null) {
            setShowEntryField(storedShowEntryField);
        }
    }, []);

    const handleMakeStartDate = (event) => {
        event.preventDefault(); // Prevent the default behavior of the button
        const newStartDate = weightDetails.date.slice(0, 10); // Get the selected date as the start date without timestamp
        console.log("New Start Date:", newStartDate); // Log the new start date
    
    
        // Filter the weightEntries array to get the entries after the new start date
        const filteredWeightEntries = weightEntries.filter((entry) => new Date(entry.date) >= new Date(newStartDate));
        console.log("Filtered Weight Entries:", filteredWeightEntries);
    
        setStartDate(newStartDate);
        
    
    const userId = loggedData.loggedUser.userid;
    const token = loggedData.loggedUser.token;

    fetch(`http://localhost:8000/users/${userId}/${newStartDate}`, {
        method: "PUT",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
            "CSRF-Token": csrfToken // Include CSRF token in headers
        },
        body: JSON.stringify({ startDate: newStartDate }),
        credentials: 'include'
    })
    .then(response => {
        console.log("PUT Response:", response); // Log the response
        if (!response.ok) {
            throw new Error("Failed to update start date");
        }
        console.log("Start date updated successfully");
    })
    .catch(error => {
        console.error("Error updating start date:", error);
    });
};
    
const fetchStartDateFromServer = () => {
    // Fetch the start date from the server
    const userId = loggedData.loggedUser.userid;
    const token = loggedData.loggedUser.token;
    fetch(`http://localhost:8000/users/${userId}/startdate`, {
        method: "GET",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
            "CSRF-Token": csrfToken // Include CSRF token in headers
        },
        credentials: 'include'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error("Failed to fetch start date from server");
        }
        // Parse the response as JSON
        return response.json();
    })
    .then(data => {
        // Set the start date from the server response
        setStartDate(data.startDate);
    })
    .catch(error => {
        console.error("Error fetching start date from server:", error);
    });
};

const handleDeleteStartDate = () => {
    const userId = loggedData.loggedUser.userid;
    const token = loggedData.loggedUser.token;
    fetch(`http://localhost:8000/users/${userId}/startdate`, {
        method: "DELETE",
        headers: {
            "Authorization": `Bearer ${token}`,
            "Content-Type": "application/json",
            "CSRF-Token": csrfToken // Include CSRF token in headers
        },
        credentials: 'include'
    })
    .then(response => {
        if (response.ok) {
            // Clear the start date in state if it's not empty
            if (startDate !== "") {
                setStartDate("");
            }
            console.log("Start date deleted successfully");
        } else {
            throw new Error("Failed to delete start date");
        }
    })
    .catch(error => {
        console.error("Error deleting start date:", error);
    });
};

return (
    <section className="container weight-container">
        <Header />
        <Footer />

        {loading ? (
            <div className="spinner-container">
                <ClipLoader
                    color={color}
                    loading={loading}
                    size={25}
                    aria-label="Loading Spinner"
                    data-testid="loader"
                />
            </div>
        ) : (
            <div>
                {/* <span onClick={handleEntryClick}>Kilo Girişi</span> */}
                <span>Kilo Girişi</span>
        
                <div className="weight-entry">
                    {showEntryField && (
                        <div className="weight-entry-start">
                            <input
                                className="date-box"
                                type="date"
                                value={weightDetails.date}
                                onChange={handleDateChange}
                            />

                            <form className="form" onSubmit={handleSubmit}>
                                <div className="weight-entry-box">
                                    <input
                                        type="number"
                                        step="0.01"
                                        onChange={handleInput}
                                        className="inp-weight"
                                        placeholder="Kilo"
                                        name="weight"
                                        value={weightDetails.weight}
                                        required
                                    />

                                    <p className="weight-entry-box-paraf">Kilonuzu sabah hiçbir şey yemeden içmeden, tuvaleti kullandıktan sonra aynı saatte tartmanız önerilmektedir.</p>
                                    <div className="weight-entry-box-wc">
                                        <p className="weight-entry-box-wc-question">Tuvalete çıktınız mı?</p>
                                        <div>
                                            <label>
                                                <input
                                                    type="radio"
                                                    name="choice"
                                                    value="✅"
                                                    onChange={handleWcInput}
                                                    checked={wcDetails.choice === "✅"} // Add this line to ensure correct default selection
                                                    required
                                                />
                                                Evet
                                            </label>
                                            <label>
                                                <input
                                                    type="radio"
                                                    name="choice"
                                                    value="❌"
                                                    onChange={handleWcInput}
                                                    checked={wcDetails.choice === "❌"} // Add this line to ensure correct default selection
                                                    required
                                                />
                                                Hayır
                                            </label>
                                        </div>
                                    </div>

                                    <div className="weight-track-btn">
                                        <button className="btn-add">+</button>
                                    </div>

                                    <div className="start-date-box">
                                        <div className="trash-can-button-group">
                                        <button type="button" onClick={handleDeleteStartDate}>
                                             <i className="fa-regular fa-trash-can"></i>
                                        </button> 
                                        <button onClick={handleMakeStartDate}>Bu tarihi başlangıç yap</button>
                                        </div>
                                        {startDate && <p className="start-date-display">Başlangıç: {new Date(startDate).toLocaleDateString('tr-TR')}</p>}                                         
                                    </div>
                                    <div className="weight-msg">
                                        <p className={message.type}>{message.text}</p>
                                    </div>
                                </div>
                                
                            </form>
                        </div>
                    )}

                </div>

                <div className="weight-data">
                    {/* Display weekly average, previous weekly average, weekly average change, and total change */}
                    <div className="weight-data-info">
                        <p className="info-title-avg">Güncel</p>
                        <p className="info-subtitle-avg">Ortalama</p>
                        <p className="info-value-avg">{weeklyAverage}kg</p>
                    </div>

                    <div className="weight-data-info">
                        <p className="info-title-avg">Önceki</p>
                        <p className="info-subtitle-avg">Ortalama</p>
                        <p className="info-value-avg">{previousWeeklyAverage}kg</p>
                    </div>

                    <div className="weight-data-info">
                        <p className="info-title">Haftalık</p>
                        <p className="info-title">Değişim</p>
                        <p className="info-value">{weeklyAverageDifference}kg</p>
                    </div>

                    <div className="weight-data-info">
                        <p className="info-title">Toplam</p>
                        <p className="info-title">Değişim</p>
                        <p className="info-value">
                        {totalDifference > 0 ? `+${totalDifference}` : totalDifference < 0 ? `${totalDifference}` : '0'}kg</p>          
                    </div>
                </div>

                {/* Display weight entries */}
                <div className="weight-entries-container">
                    {groupWeightEntriesByMonth().map(([monthYear, entries]) => (
                        <div className="weight-log-container" key={monthYear}>
                            <h2>{monthYear}</h2>
                            {entries.map((entry, index) => (
                                <div key={index} className={`weight-log ${startDate && entry.date && entry.date.substring(0, 10) === startDate.substring(0, 10) ? 'start-date' : ''}`}>
                                    <div className="weight-log-items">
                                        <div className="items-info">
                                            <p className="l-value">{new Date(entry.date).toLocaleDateString('tr-TR')} | </p>
                                            <p className="l-value">{entry.weight}kg</p>
                                            <p className="l-value">WC: {entry.choice}</p> {/* Display choice here */}
                                            <button onClick={() => handleDelete(entry._id)}>
                                                <i className="fa-regular fa-trash-can"></i>
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <div className="start-date-buttons">
                                        {startDate && startDate.substring(0, 10) && entry.date && entry.date.substring(0, 10) === startDate.substring(0, 10) && (
                                            <p className="start-date-text">Başlangıç!</p>
                                        )}

                                        {/* Button to delete start date */}
                                        {startDate && entry.date && entry.date.substring(0, 10) === startDate.substring(0, 10) && (
                                            <button onClick={handleDeleteStartDate}>
                                                <i className="fa-regular fa-trash-can"></i>
                                            </button>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    ))}
                </div>
            </div>
        )}
    </section>
)}

