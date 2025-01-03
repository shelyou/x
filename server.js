const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const app = express();
const PORT = 3000;

app.use(bodyParser.json());

// Endpoint to update price
app.post('/update-price', (req, res) => {
    const { file, index, priceType, newPrice } = req.body;

    // Load the JSON file
    fs.readFile(file, 'utf8', (err, data) => {
        if (err) return res.status(500).send('Error reading file');

        let jsonData = JSON.parse(data);
        let item = jsonData.tables[0].data[index]; // Adjust based on your JSON structure

        // Update the price based on priceType
        if (priceType === '1000_gram') {
            item.harga_1000_gram = parseFloat(newPrice);
        } else if (priceType === '500_gram') {
            item.harga_500_gram = parseFloat(newPrice);
        } else if (priceType === '250_gram') {
            item.harga_250_gram = parseFloat(newPrice);
        }

        // Save the updated JSON back to the file
        fs.writeFile(file, JSON.stringify(jsonData, null, 2), (err) => {
            if (err) return res.status(500).send('Error writing file');
            res.send('Price updated successfully');
        });
    });
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
