// Array berisi item galeri
const galleryItems = [
{ imgSrc: "IMG_8514.png", alt: "Afghanistan", label: "Afghanistan" },
{ imgSrc: "IMG_8514.png", alt: "Albania", label: "Albania" },
{ imgSrc: "IMG_8514.png", alt: "Algeria", label: "Algeria" },
{ imgSrc: "IMG_8514.png", alt: "Andorra", label: "Andorra" },
{ imgSrc: "IMG_8514.png", alt: "Angola", label: "Angola" },
{ imgSrc: "IMG_8514.png", alt: "Antigua and Barbuda", label: "Antigua and Barbuda" },
{ imgSrc: "IMG_8514.png", alt: "Argentina", label: "Argentina" },
{ imgSrc: "IMG_8514.png", alt: "Armenia", label: "Armenia" },
{ imgSrc: "IMG_8514.png", alt: "Australia", label: "Australia" },
{ imgSrc: "IMG_8514.png", alt: "Austria", label: "Austria" },
{ imgSrc: "IMG_8514.png", alt: "Azerbaijan", label: "Azerbaijan" },
{ imgSrc: "IMG_8514.png", alt: "Bahamas", label: "Bahamas" },
{ imgSrc: "IMG_8514.png", alt: "Bahrain", label: "Bahrain" },
{ imgSrc: "IMG_8514.png", alt: "Bangladesh", label: "Bangladesh" },
{ imgSrc: "IMG_8514.png", alt: "Barbados", label: "Barbados" },
{ imgSrc: "IMG_8514.png", alt: "Belarus", label: "Belarus" },
{ imgSrc: "IMG_8514.png", alt: "Belgium", label: "Belgium" },
{ imgSrc: "IMG_8514.png", alt: "Belize", label: "Belize" },
{ imgSrc: "IMG_8514.png", alt: "Benin", label: "Benin" },
{ imgSrc: "IMG_8514.png", alt: "Bhutan", label: "Bhutan" },
{ imgSrc: "IMG_8514.png", alt: "Bolivia", label: "Bolivia" },
{ imgSrc: "IMG_8514.png", alt: "Bosnia and Herzegovina", label: "Bosnia and Herzegovina" },
{ imgSrc: "IMG_8514.png", alt: "Botswana", label: "Botswana" },
{ imgSrc: "IMG_8514.png", alt: "Brazil", label: "Brazil" },
{ imgSrc: "IMG_8514.png", alt: "Brunei", label: "Brunei" },
{ imgSrc: "IMG_8514.png", alt: "Bulgaria", label: "Bulgaria" },
{ imgSrc: "IMG_8514.png", alt: "Burkina Faso", label: "Burkina Faso" },
{ imgSrc: "IMG_8514.png", alt: "Burundi", label: "Burundi" },
{ imgSrc: "IMG_8514.png", alt: "Cabo Verde", label: "Cabo Verde" },
{ imgSrc: "IMG_8514.png", alt: "Cambodia", label: "Cambodia" },
{ imgSrc: "IMG_8514.png", alt: "Cameroon", label: "Cameroon" },
{ imgSrc: "IMG_8514.png", alt: "Canada", label: "Canada" },
{ imgSrc: "IMG_8514.png", alt: "Central African Republic", label: "Central African Republic" },
{ imgSrc: "IMG_8514.png", alt: "Chad", label: "Chad" },
{ imgSrc: "IMG_8514.png", alt: "Chile", label: "Chile" },
{ imgSrc: "IMG_8514.png", alt: "China", label: "China" },
{ imgSrc: "IMG_8514.png", alt: "Colombia", label: "Colombia" },
{ imgSrc: "IMG_8514.png", alt: "Comoros", label: "Comoros" },
{ imgSrc: "IMG_8514.png", alt: "Congo (Congo-Brazzaville)", label: "Congo (Congo-Brazzaville)" },
{ imgSrc: "IMG_8514.png", alt: "Costa Rica", label: "Costa Rica" },
{ imgSrc: "IMG_8514.png", alt: "Croatia", label: "Croatia" },
{ imgSrc: "IMG_8514.png", alt: "Cuba", label: "Cuba" },
{ imgSrc: "IMG_8514.png", alt: "Cyprus", label: "Cyprus" },
{ imgSrc: "IMG_8514.png", alt: "Czech Republic", label: "Czech Republic" },
{ imgSrc: "IMG_8514.png", alt: "Denmark", label: "Denmark" },
{ imgSrc: "IMG_8514.png", alt: "Djibouti", label: "Djibouti" },
{ imgSrc: "IMG_8514.png", alt: "Dominica", label: "Dominica" },
{ imgSrc: "IMG_8514.png", alt: "Dominican Republic", label: "Dominican Republic" },
{ imgSrc: "IMG_8514.png", alt: "East Timor (Timor-Leste)", label: "East Timor (Timor-Leste)" },
{ imgSrc: "IMG_8514.png", alt: "Ecuador", label: "Ecuador" },
{ imgSrc: "IMG_8514.png", alt: "Egypt", label: "Egypt" },
{ imgSrc: "IMG_8514.png", alt: "El Salvador", label: "El Salvador" },
{ imgSrc: "IMG_8514.png", alt: "Equatorial Guinea", label: "Equatorial Guinea" },
{ imgSrc: "IMG_8514.png", alt: "Eritrea", label: "Eritrea" },
{ imgSrc: "IMG_8514.png", alt: "Estonia", label: "Estonia" },
{ imgSrc: "IMG_8514.png", alt: "Eswatini", label: "Eswatini" },
{ imgSrc: "IMG_8514.png", alt: "Ethiopia", label: "Ethiopia" },
{ imgSrc: "IMG_8514.png", alt: "Fiji", label: "Fiji" },
{ imgSrc: "IMG_8514.png", alt: "Finland", label: "Finland" },
{ imgSrc: "IMG_8514.png", alt: "France", label: "France" },
{ imgSrc: "IMG_8514.png", alt: "Gabon", label: "Gabon" },
{ imgSrc: "IMG_8514.png", alt: "Gambia", label: "Gambia" },
{ imgSrc: "IMG_8514.png", alt: "Georgia", label: "Georgia" },
{ imgSrc: "IMG_8514.png", alt: "Germany", label: "Germany" },
{ imgSrc: "IMG_8514.png", alt: "Ghana", label: "Ghana" },
{ imgSrc: "IMG_8514.png", alt: "Greece", label: "Greece" },
{ imgSrc: "IMG_8514.png", alt: "Grenada", label: "Grenada" },
{ imgSrc: "IMG_8514.png", alt: "Guatemala", label: "Guatemala" },
{ imgSrc: "IMG_8514.png", alt: "Guinea", label: "Guinea" },
{ imgSrc: "IMG_8514.png", alt: "Guinea-Bissau", label: "Guinea-Bissau" },
{ imgSrc: "IMG_8514.png", alt: "Guyana", label: "Guyana" },
{ imgSrc: "IMG_8514.png", alt: "Haiti", label: "Haiti" },
{ imgSrc: "IMG_8514.png", alt: "Honduras", label: "Honduras" },
{ imgSrc: "IMG_8514.png", alt: "Hungary", label: "Hungary" },
{ imgSrc: "IMG_8514.png", alt: "Iceland", label: "Iceland" },
{ imgSrc: "IMG_8514.png", alt: "India", label: "India" },
{ imgSrc: "IMG_8514.png", alt: "Indonesia", label: "Indonesia" },
{ imgSrc: "IMG_8514.png", alt: "Iran", label: "Iran" },
{ imgSrc: "IMG_8514.png", alt: "Iraq", label: "Iraq" },
{ imgSrc: "IMG_8514.png", alt: "Ireland", label: "Ireland" },
{ imgSrc: "IMG_8514.png", alt: "Israel", label: "Israel" },
{ imgSrc: "IMG_8514.png", alt: "Italy", label: "Italy" },
{ imgSrc: "IMG_8514.png", alt: "Ivory Coast (Côte d’Ivoire)", label: "Ivory Coast (Côte d’Ivoire)" },
{ imgSrc: "IMG_8514.png", alt: "Jamaica", label: "Jamaica" },
{ imgSrc: "IMG_8514.png", alt: "Japan", label: "Japan" },
{ imgSrc: "IMG_8514.png", alt: "Jordan", label: "Jordan" },
{ imgSrc: "IMG_8514.png", alt: "Kazakhstan", label: "Kazakhstan" },
{ imgSrc: "IMG_8514.png", alt: "Kenya", label: "Kenya" },
{ imgSrc: "IMG_8514.png", alt: "Kiribati", label: "Kiribati" },
{ imgSrc: "IMG_8514.png", alt: "Korea, North (North Korea)", label: "Korea, North (North Korea)" },
{ imgSrc: "IMG_8514.png", alt: "Korea, South (South Korea)", label: "Korea, South (South Korea)" },
{ imgSrc: "IMG_8514.png", alt: "Kuwait", label: "Kuwait" },
{ imgSrc: "IMG_8514.png", alt: "Kyrgyzstan", label: "Kyrgyzstan" },
{ imgSrc: "IMG_8514.png", alt: "Laos", label: "Laos" },
{ imgSrc: "IMG_8514.png", alt: "Latvia", label: "Latvia" },
{ imgSrc: "IMG_8514.png", alt: "Lebanon", label: "Lebanon" },
{ imgSrc: "IMG_8514.png", alt: "Lesotho", label: "Lesotho" },
{ imgSrc: "IMG_8514.png", alt: "Liberia", label: "Liberia" },
{ imgSrc: "IMG_8514.png", alt: "Libya", label: "Libya" },
{ imgSrc: "IMG_8514.png", alt: "Liechtenstein", label: "Liechtenstein" },
{ imgSrc: "IMG_8514.png", alt: "Lithuania", label: "Lithuania" },
{ imgSrc: "IMG_8514.png", alt: "Luxembourg", label: "Luxembourg" },
{ imgSrc: "IMG_8514.png", alt: "Madagascar", label: "Madagascar" },
{ imgSrc: "IMG_8514.png", alt: "Malawi", label: "Malawi" },
{ imgSrc: "IMG_8514.png", alt: "Malaysia", label: "Malaysia" },
{ imgSrc: "IMG_8514.png", alt: "Maldives", label: "Maldives" },
{ imgSrc: "IMG_8514.png", alt: "Mali", label: "Mali" },
{ imgSrc: "IMG_8514.png", alt: "Malta", label: "Malta" },
{ imgSrc: "IMG_8514.png", alt: "Marshall Islands", label: "Marshall Islands" },
{ imgSrc: "IMG_8514.png", alt: "Mauritania", label: "Mauritania" },
{ imgSrc: "IMG_8514.png", alt: "Mauritius", label: "Mauritius" },
{ imgSrc: "IMG_8514.png", alt: "Mexico", label: "Mexico" },
{ imgSrc: "IMG_8514.png", alt: "Micronesia", label: "Micronesia" },
{ imgSrc: "IMG_8514.png", alt: "Moldova", label: "Moldova" },
{ imgSrc: "IMG_8514.png", alt: "Monaco", label: "Monaco" },
{ imgSrc: "IMG_8514.png", alt: "Mongolia", label: "Mongolia" },
{ imgSrc: "IMG_8514.png", alt: "Montenegro", label: "Montenegro" },
{ imgSrc: "IMG_8514.png", alt: "Morocco", label: "Morocco" },
{ imgSrc: "IMG_8514.png", alt: "Mozambique", label: "Mozambique" },
{ imgSrc: "IMG_8514.png", alt: "Myanmar (Burma)", label: "Myanmar (Burma)" },
{ imgSrc: "IMG_8514.png", alt: "Namibia", label: "Namibia" },
{ imgSrc: "IMG_8514.png", alt: "Nauru", label: "Nauru" },
{ imgSrc: "IMG_8514.png", alt: "Nepal", label: "Nepal" },
{ imgSrc: "IMG_8514.png", alt: "Netherlands", label: "Netherlands" },
{ imgSrc: "IMG_8514.png", alt: "New Zealand", label: "New Zealand" },
{ imgSrc: "IMG_8514.png", alt: "Nicaragua", label: "Nicaragua" },
{ imgSrc: "IMG_8514.png", alt: "Niger", label: "Niger" },
{ imgSrc: "IMG_8514.png", alt: "Nigeria", label: "Nigeria" },
{ imgSrc: "IMG_8514.png", alt: "North Macedonia", label: "North Macedonia" },
{ imgSrc: "IMG_8514.png", alt: "Norway", label: "Norway" },
{ imgSrc: "IMG_8514.png", alt: "Oman", label: "Oman" },
{ imgSrc: "IMG_8514.png", alt: "Pakistan", label: "Pakistan" },
{ imgSrc: "IMG_8514.png", alt: "Palau", label: "Palau" },
{ imgSrc: "IMG_8514.png", alt: "Panama", label: "Panama" },
{ imgSrc: "IMG_8514.png", alt: "Papua New Guinea", label: "Papua New Guinea" },
{ imgSrc: "IMG_8514.png", alt: "Paraguay", label: "Paraguay" },
{ imgSrc: "IMG_8514.png", alt: "Peru", label: "Peru" },
{ imgSrc: "IMG_8514.png", alt: "Philippines", label: "Philippines" },
{ imgSrc: "IMG_8514.png", alt: "Poland", label: "Poland" },
{ imgSrc: "IMG_8514.png", alt: "Portugal", label: "Portugal" },
{ imgSrc: "IMG_8514.png", alt: "Qatar", label: "Qatar" },
{ imgSrc: "IMG_8514.png", alt: "Romania", label: "Romania" },
{ imgSrc: "IMG_8514.png", alt: "Russia", label: "Russia" },
{ imgSrc: "IMG_8514.png", alt: "Rwanda", label: "Rwanda" },
{ imgSrc: "IMG_8514.png", alt: "Saint Kitts and Nevis", label: "Saint Kitts and Nevis" },
{ imgSrc: "IMG_8514.png", alt: "Saint Lucia", label: "Saint Lucia" },
{ imgSrc: "IMG_8514.png", alt: "Saint Vincent and the Grenadines", label: "Saint Vincent and the Grenadines" },
{ imgSrc: "IMG_8514.png", alt: "Samoa", label: "Samoa" },
{ imgSrc: "IMG_8514.png", alt: "San Marino", label: "San Marino" },
{ imgSrc: "IMG_8514.png", alt: "Sao Tome and Principe", label: "Sao Tome and Principe" },
{ imgSrc: "IMG_8514.png", alt: "Saudi Arabia", label: "Saudi Arabia" },
{ imgSrc: "IMG_8514.png", alt: "Senegal", label: "Senegal" },
{ imgSrc: "IMG_8514.png", alt: "Serbia", label: "Serbia" },
{ imgSrc: "IMG_8514.png", alt: "Seychelles", label: "Seychelles" },
{ imgSrc: "IMG_8514.png", alt: "Sierra Leone", label: "Sierra Leone" },
{ imgSrc: "IMG_8514.png", alt: "Singapore", label: "Singapore" },
{ imgSrc: "IMG_8514.png", alt: "Slovakia", label: "Slovakia" },
{ imgSrc: "IMG_8514.png", alt: "Slovenia", label: "Slovenia" },
{ imgSrc: "IMG_8514.png", alt: "Solomon Islands", label: "Solomon Islands" },
{ imgSrc: "IMG_8514.png", alt: "Somalia", label: "Somalia" },
{ imgSrc: "IMG_8514.png", alt: "South Africa", label: "South Africa" },
{ imgSrc: "IMG_8514.png", alt: "South Sudan", label: "South Sudan" },
{ imgSrc: "IMG_8514.png", alt: "Spain", label: "Spain" },
{ imgSrc: "IMG_8514.png", alt: "Sri Lanka", label: "Sri Lanka" },
{ imgSrc: "IMG_8514.png", alt: "Sudan", label: "Sudan" },
{ imgSrc: "IMG_8514.png", alt: "Suriname", label: "Suriname" },
{ imgSrc: "IMG_8514.png", alt: "Sweden", label: "Sweden" },
{ imgSrc: "IMG_8514.png", alt: "Switzerland", label: "Switzerland" },
{ imgSrc: "IMG_8514.png", alt: "Syria", label: "Syria" },
{ imgSrc: "IMG_8514.png", alt: "Taiwan", label: "Taiwan" },
{ imgSrc: "IMG_8514.png", alt: "Tajikistan", label: "Tajikistan" },
{ imgSrc: "IMG_8514.png", alt: "Tanzania", label: "Tanzania" },
{ imgSrc: "IMG_8514.png", alt: "Thailand", label: "Thailand" },
{ imgSrc: "IMG_8514.png", alt: "Togo", label: "Togo" },
{ imgSrc: "IMG_8514.png", alt: "Tonga", label: "Tonga" },
{ imgSrc: "IMG_8514.png", alt: "Trinidad and Tobago", label: "Trinidad and Tobago" },
{ imgSrc: "IMG_8514.png", alt: "Tunisia", label: "Tunisia" },
{ imgSrc: "IMG_8514.png", alt: "Turkey", label: "Turkey" },
{ imgSrc: "IMG_8514.png", alt: "Turkmenistan", label: "Turkmenistan" },
{ imgSrc: "IMG_8514.png", alt: "Tuvalu", label: "Tuvalu" },
{ imgSrc: "IMG_8514.png", alt: "Uganda", label: "Uganda" },
{ imgSrc: "IMG_8514.png", alt: "Ukraine", label: "Ukraine" },
{ imgSrc: "IMG_8514.png", alt: "United Arab Emirates (UAE)", label: "United Arab Emirates (UAE)" },
{ imgSrc: "IMG_8514.png", alt: "United Kingdom (UK)", label: "United Kingdom (UK)" },
{ imgSrc: "IMG_8514.png", alt: "United States", label: "United States" },
{ imgSrc: "IMG_8514.png", alt: "Uruguay", label: "Uruguay" },
{ imgSrc: "IMG_8514.png", alt: "Uzbekistan", label: "Uzbekistan" },
{ imgSrc: "IMG_8514.png", alt: "Vanuatu", label: "Vanuatu" },
{ imgSrc: "IMG_8514.png", alt: "Vatican City (Holy See)", label: "Vatican City (Holy See)" },
{ imgSrc: "IMG_8514.png", alt: "Venezuela", label: "Venezuela" },
{ imgSrc: "IMG_8514.png", alt: "Vietnam", label: "Vietnam" },
{ imgSrc: "IMG_8514.png", alt: "Yemen", label: "Yemen" },
{ imgSrc: "IMG_8514.png", alt: "Zambia", label: "Zambia" }
{ imgSrc: "IMG_8514.png", alt: "Holy See (Vatican City)", label: "Holy See (Vatican City)" },
{ imgSrc: "IMG_8514.png", alt: "Palestine", label: "Palestine" },
];

// Fungsi untuk membuat elemen galeri
function createGalleryItem(item) {
    const galleryItem = document.createElement("div");
    galleryItem.className = "gallery-item";
    galleryItem.setAttribute("onclick", "flipImage(this)");

    const galleryItemInner = document.createElement("div");
    galleryItemInner.className = "gallery-item-inner";

    const galleryFront = document.createElement("div");
    galleryFront.className = "gallery-front";
    const img = document.createElement("img");
    img.src = item.imgSrc;
    img.alt = item.alt;
    galleryFront.appendChild(img);

    const galleryBack = document.createElement("div");
    galleryBack.className = "gallery-back";
    galleryBack.textContent = item.label;
    galleryBack.setAttribute(
        "onclick",
        `handleBackClick('${item.label}', event); checkStorageAndDownload('${item.label}')`
    );

    galleryItemInner.appendChild(galleryFront);
    galleryItemInner.appendChild(galleryBack);
    galleryItem.appendChild(galleryItemInner);

    return galleryItem;
}

// Fungsi untuk membangun galeri
function buildGallery() {
    const galleryContainer = document.querySelector(".gallery-container .gallery");

    if (!galleryContainer) {
        console.error("Gallery container not found!");
        return;
    }

    galleryItems.forEach((item) => {
        const galleryItem = createGalleryItem(item);
        galleryContainer.appendChild(galleryItem);
    });
}

// Fungsi untuk membalik gambar
function flipImage(item) {
    const allItems = document.querySelectorAll('.gallery-item');
    allItems.forEach((el) => {
        if (el !== item) {
            el.classList.remove('flipped');
        }
    });
    item.classList.toggle('flipped');
}

// Fungsi untuk menangani klik di luar gambar
function handleOutsideClick(event) {
    const galleryItems = document.querySelectorAll('.gallery-item');
    galleryItems.forEach((item) => {
        if (!item.contains(event.target)) {
            item.classList.remove('flipped');
        }
    });
}

// Fungsi untuk menangani klik pada bagian belakang gambar
function handleBackClick(country, event) {
    event.stopPropagation();
    alert('You clicked on the back of the image for ' + country);
}

// Daftarkan event listener saat halaman selesai dimuat
document.addEventListener("DOMContentLoaded", buildGallery);
document.addEventListener('click', handleOutsideClick);
