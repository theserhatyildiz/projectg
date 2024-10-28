import { UserContext } from "../context/UserContext";
import { useContext, useEffect, useState } from "react";
import { useNavigate, Link } from "react-router-dom";
import '@fortawesome/fontawesome-free/css/all.css';
import { format } from 'date-fns';

export default function Meal({ items, mealNumber, eatenDate, deleteFood }) {
    const { loggedUser } = useContext(UserContext);
    const [filteredItems, setFilteredItems] = useState([]);
    const [mealTotal, setMealTotal] = useState({
        totalCalories: 0,
        totalProtein: 0,
        totalCarbs: 0,
        totalFats: 0,
        totalFiber: 0
    });
    const [showFoods, setShowFoods] = useState(true); // State to control whether to show or hide foods

    useEffect(() => {
        const filtered = items.filter((item) => item.mealNumber === mealNumber);
        setFilteredItems(filtered);
        calculateMealTotal(filtered);
    }, [items, mealNumber]);

    // console.log("Meal items:", { items });

    const navigate = useNavigate();

    // Bunlarin "foodId, initialValues, details, quantity, id, mealNumber, eatenDat" yapacaklari asagidaki handleFoodClick fonksiyonunda belirtiliyor.
    // Ve hepsi asagidaki handleFoodClick fonksiyonundaki siralamayi takip ediyor.
    // mesela initialValues adini ben verdim ve data aslinda buradan geliyor = item.foodId
    // console.log yaptiginda datayi initialValues olarak gorursun.
    
    const handleFoodClick = (foodId, initialValues, details, quantity, id, mealNumber, eatenDate) => {
        // console.log("handleFoodClick parameters:", { foodId, initialValues, details, quantity, id, mealNumber, eatenDate });
        navigate("/fooddata", { state: { foodId, initialValues, quantity, details, id, mealNumber, eatenDate } });
    };

    const handleAddFoodClick = () => {
        navigate("/search", { state: { mealNumber, eatenDate } });
    };

    const calculateMealTotal = (mealItems) => {
        let total = {
            totalCalories: 0,
            totalProtein: 0,
            totalCarbs: 0,
            totalFats: 0,
            totalFiber: 0
        };

        mealItems.forEach((item) => {
            total.totalCalories += item.details.Calorie;
            total.totalProtein += item.details.Protein;
            total.totalCarbs += item.details.Carbohydrate;
            total.totalFats += item.details.Fat;
            total.totalFiber += item.details.Fiber;
        });

        setMealTotal({
            totalCalories: parseFloat(total.totalCalories.toFixed(2)),
            totalProtein: parseFloat(total.totalProtein.toFixed(2)),
            totalCarbs: parseFloat(total.totalCarbs.toFixed(2)),
            totalFats: parseFloat(total.totalFats.toFixed(2)),
            totalFiber: parseFloat(total.totalFiber.toFixed(2))
        });
    };

    const handleMealClick = () => {
        setShowFoods(!showFoods);
    };

    function formatNumber(number) {
        if (number % 1 === 0) {
            return number.toString(); // No decimals if the number is an integer
        } else {
            return parseFloat(number.toFixed(1)).toString(); // Convert to float to remove trailing zeros and then to string
        }
    }
    
      // Format the eatenDate using date-fns for mealFunction page
      const formattedDate = format(new Date(eatenDate), 'yyyy-MM-dd'); // Adjust format as needed
    
    return (
        <div className="meal-container">
            <div className="meal-info">
                <p className="meal-num" onClick={handleMealClick}>{mealNumber}.Öğün</p>
                {filteredItems.length > 0 && (
                    <div className="summary">
                        <div className="summary-item">
                            <p className="s-title">Kal</p>
                            <p className="s-value">{formatNumber(mealTotal.totalCalories)}</p>
                        </div>
                        <div className="summary-item">
                            <p className="s-title">Pro</p>
                            <p className="s-value">{formatNumber(mealTotal.totalProtein)}g</p>
                        </div>
                        <div className="summary-item">
                            <p className="s-title">Karb</p>
                            <p className="s-value">{formatNumber(mealTotal.totalCarbs)}g</p>
                        </div>
                        <div className="summary-item">
                            <p className="s-title">Yağ</p>
                            <p className="s-value">{formatNumber(mealTotal.totalFats)}g</p>
                        </div>
                        <div className="summary-item">
                            <p className="s-title">Lif</p>
                            <p className="s-value">{formatNumber(mealTotal.totalFiber)}g</p>
                        </div>
                    </div>
                )}
            </div>

            {showFoods && (
                <div>
                    {filteredItems.map((item) => (
                        <div className="item" key={item._id}>
                            <h3 className="food-heading" onClick={() => handleFoodClick(item.foodId._id, item.foodId, item.details, item.quantity, item._id, item.mealNumber, item.eatenDate)}>{item.details.Name}</h3>
                            <div className="food-info-container">
                                <div className="food-info" onClick={() => handleFoodClick(item.foodId._id, item.foodId, item.details, item.quantity, item._id, item.mealNumber, item.eatenDate)}>
                                    <h4>{item.quantity}g -</h4>
                                    <p>{formatNumber(item.details.Calorie)} kal: {formatNumber(item.details.Protein)}p, {formatNumber(item.details.Carbohydrate)}k, {formatNumber(item.details.Fat)}y, {formatNumber(item.details.Fiber)}lif  </p>
                                </div>
                                <button onClick={() => deleteFood(item._id)}>
                                    <i className="fa-regular fa-trash-can"></i>
                                </button>
                            </div>
                        </div>
                    ))}
                </div>
            )}

            <div className="btn-group">
                <div className="btn-group-add">
                    <button className="btn" onClick={handleAddFoodClick}>+</button>
                </div>

                <Link to={`/mealFunctions?mealNumber=${mealNumber}&eatenDate=${formattedDate}`}>
                    <button className="btn-group-function">...</button>
                </Link>
            </div>
        </div>
    );
}
