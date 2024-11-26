// Array berisi item galeri
const galleryItems = [
    { imgSrc: "IMG_8514.png", alt: "Russia", label: "Russia" },
    { imgSrc: "IMG_8514.png", alt: "Canada", label: "Canada" },
    { imgSrc: "https://drive.google.com/uc?export=view&id=1dQfWu2ljJcSqPhYuwS66nIhprNzT9T4o", alt: "United States", label: "United States" },
    { imgSrc: "IMG_8514.png", alt: "China", label: "China" },
    { imgSrc: "IMG_8514.png", alt: "Brazil", label: "Brazil" },
    { imgSrc: "IMG_8514.png", alt: "Australia", label: "Australia" },
    { imgSrc: "IMG_8514.png", alt: "India", label: "India" },
    { imgSrc: "IMG_8514.png", alt: "Argentina", label: "Argentina" },
    { imgSrc: "IMG_8514.png", alt: "Kazakhstan", label: "Kazakhstan" },
    { imgSrc: "IMG_8514.png", alt: "Algeria", label: "Algeria" },
    { imgSrc: "IMG_8514.png", alt: "Congo, Democratic Republic of the", label: "Congo, Democratic Republic of the" },
    { imgSrc: "IMG_8514.png", alt: "Greenland (Denmark)", label: "Greenland (Denmark)" },
    { imgSrc: "IMG_8514.png", alt: "Saudi Arabia", label: "Saudi Arabia" },
    { imgSrc: "IMG_8514.png", alt: "Mexico", label: "Mexico" },
    { imgSrc: "IMG_8514.png", alt: "Indonesia", label: "Indonesia" },
    { imgSrc: "IMG_8514.png", alt: "Sudan", label: "Sudan" },
    { imgSrc: "IMG_8514.png", alt: "Libya", label: "Libya" },
    { imgSrc: "IMG_8514.png", alt: "Chad", label: "Chad" },
    { imgSrc: "IMG_8514.png", alt: "Niger", label: "Niger" },
    { imgSrc: "IMG_8514.png", alt: "Angola", label: "Angola" },
    { imgSrc: "IMG_8514.png", alt: "Mali", label: "Mali" },
    { imgSrc: "IMG_8514.png", alt: "South Africa", label: "South Africa" }
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
