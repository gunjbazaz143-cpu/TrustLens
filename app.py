"""
TrustLens - AI Based Information Verification System
app.py - application factory, database seeding, error handlers.

Run locally:
    python app.py
or with a custom port (the default 5000 may be taken by another service):
    TRUSTLENS_PORT=5001 python app.py
"""
import os
from datetime import datetime, timezone

from flask import Flask, redirect, render_template, url_for
from flask_login import LoginManager, current_user
from flask_mail import Mail

from config import Config
from models import KnowledgeItem, Setting, User, db

mail = Mail()
login_manager = LoginManager()

# --------------------------------------------------------------------------- #
#  Seed data
# --------------------------------------------------------------------------- #

KNOWLEDGE_SEED = [
    # (claim, verdict, category, evidence, source)
    ("The Earth revolves around the Sun, not the other way around.",
     "true", "Science", "Heliocentric model confirmed by centuries of observation and orbital mechanics.",
     "NASA Science"),
    ("Humans only use 10 percent of their brain.",
     "false", "Health", "Neuroimaging shows activity across nearly all brain regions; the 10% claim is a myth.",
     "Scientific American"),
    ("Vaccines do not cause autism.",
     "true", "Health", "Large-scale studies show no link between vaccination and autism.",
     "WHO"),
    ("Eating carrots can improve night vision.",
     "false", "Health", "Vitamin A deficiency causes night blindness, but carrots do not boost normal vision.",
     "Harvard Medical School"),
    ("India's national animal is the Bengal tiger.",
     "true", "General", "The Bengal tiger was declared India's national animal in 1972.",
     "Govt. of India"),
    ("Bats are completely blind.",
     "false", "Science", "Most bats have functional eyesight; many also use echolocation.",
     "National Geographic"),
    ("The Great Wall of China is visible from space with the naked eye.",
     "false", "Space", "Astronauts report it is not visible without aid under normal conditions.",
     "NASA"),
    ("Drinking water in the Sahara is not the reason most tourists get sick.",
     "true", "Health", "Contaminated water and food are the leading causes of traveller's illness.",
     "CDC"),
    ("Money does not have to be physically present for a bank transfer to be real.",
     "true", "Finance", "Wire and UPI transfers are legitimate digital movements of funds.",
     "RBI"),
    ("Email or SMS asking you to pay a fee to receive a prize is a scam.",
     "true", "Fraud", "Legitimate prize organisers never ask winners to pay an advance fee.",
     "Cyber Crime Helpline"),
    # --- Health -----------------------------------------------------------
    ("Reading for 30 minutes a day can help reduce stress.",
     "true", "Health", "Reading lowers heart rate and muscle tension; a University of Sussex study found reading can cut stress by up to 68 percent.",
     "University of Sussex / NHS"),
    ("Sleeping less than seven hours a night is linked to a range of health problems.",
     "true", "Health", "Chronic short sleep is associated with higher risk of obesity, diabetes and heart disease.",
     "American Heart Association"),
    ("The common cold is caused by a virus.",
     "true", "Health", "Most colds are caused by rhinoviruses and other respiratory viruses.",
     "CDC"),
    ("Antibiotics are effective against viruses.",
     "false", "Health", "Antibiotics kill bacteria, not viruses, and overuse drives antibiotic resistance.",
     "WHO"),
    ("Fever is a sign that the body is fighting an infection.",
     "true", "Health", "A raised body temperature helps the immune system fight pathogens.",
     "Mayo Clinic"),
    ("Vitamin C can cure the common cold.",
     "false", "Health", "Vitamin C may slightly shorten a cold but does not cure or prevent it.",
     "Cochrane Review"),
    ("Sugar causes hyperactivity in children.",
     "false", "Health", "Controlled studies find no link between sugar and hyperactive behaviour in children.",
     "JAMA / NHS"),
    ("Cracking your knuckles causes arthritis.",
     "false", "Health", "Studies show no association between knuckle cracking and arthritis.",
     "Arthritis Foundation"),
    ("Reading in dim light damages your eyes.",
     "false", "Health", "Dim light can cause temporary eye strain but no permanent damage.",
     "American Academy of Ophthalmology"),
    ("Cold weather by itself makes you sick.",
     "false", "Health", "Viruses spread more indoors in cold months, but cold air alone does not cause illness.",
     "Harvard Health"),
    ("You lose most of your body heat through your head.",
     "false", "Health", "Heat loss is proportional to exposed skin area; the head is not special.",
     "BMJ"),
    ("Vitamin D is produced by the skin when exposed to sunlight.",
     "true", "Health", "UVB radiation triggers vitamin D synthesis in the skin.",
     "NIH Office of Dietary Supplements"),
    ("Regular aerobic exercise strengthens the heart.",
     "true", "Health", "Aerobic activity improves cardiovascular fitness and reduces heart-disease risk.",
     "American Heart Association"),
    ("Exercise releases endorphins which can improve mood.",
     "true", "Health", "Physical activity triggers endorphin release, reducing perceived pain and boosting mood.",
     "Harvard Medical School"),
    ("Meditation can help reduce stress and anxiety.",
     "true", "Health", "Mindfulness practice is linked to lower stress and anxiety in multiple studies.",
     "Johns Hopkins Medicine"),
    ("The five-second rule says dropped food is safe to eat.",
     "false", "Health", "Bacteria can contaminate food on contact; the time limit is a myth.",
     "Rutgers University"),
    ("Blood inside your veins is blue.",
     "false", "Health", "Blood is always red; veins look blue because of how light passes through skin.",
     "LiveScience / NIH"),
    ("The skin is the largest organ of the human body.",
     "true", "Health", "Skin is the body's largest organ, covering about two square metres.",
     "NIH / Johns Hopkins"),
    ("Stretching before exercise always prevents injury.",
     "false", "Health", "Static stretching before exercise has not been proven to prevent injury; a warm-up is more effective.",
     "Cochrane Review"),
    ("Detox diets remove toxins from the body.",
     "false", "Health", "The liver and kidneys already remove toxins; no evidence supports detox products.",
     "British Dietetic Association"),
    # --- Science / Space / Nature -------------------------------------------
    ("Water boils at 100 degrees Celsius at sea level.",
     "true", "Science", "At one atmosphere of pressure, pure water boils at 100 C.",
     "Encyclopaedia Britannica"),
    ("Goldfish have a three-second memory.",
     "false", "Science", "Goldfish can learn and remember tasks for months.",
     "Plymouth University"),
    ("Bananas grow on trees.",
     "false", "Science", "Banana plants are giant herbs, not trees.",
     "Kew Gardens"),
    ("Chameleons change colour mainly to blend in with their surroundings.",
     "false", "Science", "Chameleons change colour mainly to communicate and regulate temperature.",
     "National Geographic"),
    ("Ostriches bury their heads in the sand.",
     "false", "Science", "Ostriches do not bury their heads; the myth comes from nesting behaviour.",
     "National Geographic"),
    ("Humans have exactly five senses.",
     "false", "Science", "Humans have more than five senses, including balance, temperature and proprioception.",
     "BBC Science Focus"),
    ("Lightning never strikes the same place twice.",
     "false", "Science", "Tall structures like the Empire State Building are struck repeatedly.",
     "NOAA"),
    ("Penguins can fly.",
     "false", "Science", "Penguins are flightless birds adapted for swimming.",
     "National Geographic"),
    ("Bulls are enraged by the colour red.",
     "false", "Science", "Bulls are red-green colour blind; they react to movement.",
     "University of Pennsylvania"),
    ("Mount Everest is the tallest mountain above sea level.",
     "true", "Geography", "At 8,849 m Everest is the highest summit above sea level.",
     "National Geographic"),
    ("The Sahara is the largest desert on Earth.",
     "false", "Geography", "Antarctica is the largest desert; the Sahara is the largest hot desert.",
     "NASA Earth Observatory"),
    ("The capital of Australia is Sydney.",
     "false", "Geography", "The capital of Australia is Canberra.",
     "Commonwealth of Australia"),
    ("The capital of India is New Delhi.",
     "true", "Geography", "New Delhi has been India's capital since 1911.",
     "Govt. of India"),
    ("The Amazon rainforest produces 20 percent of the world's oxygen.",
     "false", "Science", "Ocean phytoplankton produce most oxygen; the Amazon contributes only a few percent.",
     "Scientific American"),
    ("Trees absorb carbon dioxide and release oxygen.",
     "true", "Science", "Photosynthesis consumes CO2 and releases oxygen.",
     "US Forest Service"),
    ("The sun is a star.",
     "true", "Science", "The Sun is a G-type main-sequence star at the centre of the Solar System.",
     "NASA"),
    ("The moon causes ocean tides.",
     "true", "Science", "Gravitational pull of the Moon (and Sun) drives the tides.",
     "NOAA"),
    ("The universe began with the Big Bang.",
     "true", "Science", "Cosmic microwave background and redshift support the Big Bang model.",
     "NASA / ESA"),
    ("Black holes absorb everything, including light.",
     "true", "Science", "The event horizon of a black hole traps all matter and light.",
     "NASA"),
    ("Glass is a liquid that flows slowly over time.",
     "false", "Science", "Glass is an amorphous solid; it does not flow in window panes.",
     "Corning Museum of Glass"),
    ("Diamonds are made of carbon.",
     "true", "Science", "Diamonds are a crystalline form of pure carbon.",
     "Gemological Institute of America"),
    # --- Productivity / Psychology --------------------------------------------
    ("Multitasking makes you more productive.",
     "false", "Productivity", "Task switching costs time and reduces accuracy; focus on one task is more efficient.",
     "Stanford University"),
    ("Taking regular breaks improves focus and productivity.",
     "true", "Productivity", "Breaks restore attention and prevent mental fatigue.",
     "American Psychological Association"),
    ("The Pomodoro technique uses 25-minute focused work intervals.",
     "true", "Productivity", "The Pomodoro method alternates 25-minute sprints with short breaks.",
     "Francesco Cirillo"),
    ("Learning a second language improves cognitive function.",
     "true", "Science", "Bilingualism is linked to better executive function and delayed cognitive decline.",
     "APA / NIH"),
    ("Reading fiction increases empathy.",
     "true", "Psychology", "Literary fiction engages theory-of-mind networks linked to empathy.",
     "Science / APA"),
    ("Napping during the day is always a sign of laziness.",
     "false", "Health", "Short naps can improve alertness and performance.",
     "NASA / Sleep Foundation"),
    ("Walking 10,000 steps a day is a scientifically proven requirement for good health.",
     "false", "Health", "The 10,000 target came from a 1960s marketing campaign; lower step counts still benefit health.",
     "JAMA / BBC"),
    ("Left-handed people are more intelligent.",
     "false", "Psychology", "No reliable evidence links handedness to higher intelligence.",
     "NIH"),
    # --- General knowledge -----------------------------------------------------
    ("The Statue of Liberty is located in New York.",
     "true", "General", "The statue stands on Liberty Island in New York Harbour.",
     "US National Park Service"),
    ("The currency of Japan is the Yen.",
     "true", "General", "The official currency of Japan is the yen.",
     "Bank of Japan"),
    ("The Pacific Ocean is the largest ocean on Earth.",
     "true", "Geography", "The Pacific covers more area than all land combined.",
     "NOAA"),
    ("Mount Everest was formed by the collision of tectonic plates.",
     "true", "Geography", "The Indo-Australian and Eurasian plates created the Himalayas.",
     "USGS"),
    ("The internet was originally developed as a US military research network.",
     "true", "Technology", "ARPANET, funded by the US Department of Defense, was the internet's precursor.",
     "Internet Society"),
    ("Wi-Fi signals are harmful to human health.",
     "false", "Health", "Wi-Fi uses low-power radio waves well within international safety limits.",
     "WHO"),
    ("Electric cars have zero tailpipe emissions.",
     "true", "Technology", "Battery-electric vehicles produce no exhaust emissions while driving.",
     "US EPA"),
    ("Microwave ovens make food radioactive.",
     "false", "Science", "Microwave radiation is non-ionising and leaves no radioactivity in food.",
     "WHO / FDA"),
    ("Adding salt to water makes it boil faster.",
     "false", "Science", "Salt actually raises the boiling point, so salted water boils slightly slower.",
     "USDA"),
    ("Dogs' mouths are cleaner than human mouths.",
     "false", "Health", "Human and dog mouths both contain many bacteria; neither is 'cleaner'.",
     "Cleveland Clinic"),
    ("Plastic is biodegradable.",
     "false", "Science", "Conventional plastics can take centuries to break down and are not biodegradable.",
     "US EPA"),
    ("The human body of an adult has 206 bones.",
     "true", "Health", "Adults typically have 206 bones; babies have about 270.",
     "NIH / Cleveland Clinic"),
    ("Shaving makes hair grow back thicker.",
     "false", "Health", "Shaving cuts hair at a blunt angle; growth rate and thickness are unchanged.",
     "Mayo Clinic"),
    ("The tongue has separate taste zones for sweet, sour, salty and bitter.",
     "false", "Health", "Taste buds for all basic tastes are distributed across the tongue.",
     "Scientific American"),
    ("Bacteria are the cause of all diseases.",
     "false", "Health", "Diseases can be caused by viruses, fungi, genetics and other factors, not only bacteria.",
     "NIH"),
    ("People swallow spiders while sleeping.",
     "false", "General", "There is no evidence people regularly swallow spiders in their sleep.",
     "LiveScience"),
    ("Gold is an excellent conductor of electricity.",
     "true", "Science", "Gold is highly conductive and corrosion resistant, used in electronics.",
     "Royal Society of Chemistry"),
    ("The Great Barrier Reef is the largest coral reef system in the world.",
     "true", "Geography", "It spans over 2,300 km off Australia's coast.",
     "UNESCO"),
    ("Antarctica is the coldest continent on Earth.",
     "true", "Geography", "Antarctica holds the record for the lowest surface temperature on Earth.",
     "NASA / NOAA"),
    ("GMO foods are poisonous to humans.",
     "false", "Health", "Genetically modified crops approved for sale are safe to eat according to major scientific bodies.",
     "WHO / National Academies"),
    ("Organic food is always more nutritious than non-organic food.",
     "false", "Health", "Evidence does not consistently show organic food is more nutritious.",
     "Stanford University"),
    ("Gluten-free food is healthier for everyone.",
     "false", "Health", "A gluten-free diet is only necessary for people with coeliac disease or gluten sensitivity.",
     "Harvard Health"),
    ("Coffee dehydrates you.",
     "false", "Health", "Moderate coffee intake is hydrating despite its mild diuretic effect.",
     "Journal of the American College of Nutrition"),
    ("The heart pumps blood around the body.",
     "true", "Health", "The heart is a muscular pump that circulates blood through the vascular system.",
     "NIH"),
    ("Dinosaurs became extinct after a large asteroid struck Earth.",
     "true", "Science", "The Chicxulub impact 66 million years ago is the leading explanation for dinosaur extinction.",
     "NASA / Science"),
    ("The Great Pyramid of Giza was the tallest man-made structure for thousands of years.",
     "true", "General", "It held the height record for roughly 3,800 years until Lincoln Cathedral.",
     "Encyclopaedia Britannica"),
    ("Newborn babies have kneecaps.",
     "false", "Health", "Babies are born with cartilage where kneecaps will later ossify.",
     "Mayo Clinic"),
    ("The heart stops when you sneeze.",
     "false", "Health", "Sneezing does not stop the heart; it may briefly disrupt rhythm.",
     "Cleveland Clinic"),
    ("Cats can see in total darkness.",
     "false", "Science", "Cats need some light; they see far better than humans in dim light.",
     "National Geographic"),
    ("The longest river in the world is generally considered the Nile.",
     "true", "Geography", "The Nile is traditionally cited as the world's longest river.",
     "Britannica / USGS"),
]


def seed_data():
    """Idempotent seeding: admin account, system settings, knowledge items."""
    if User.query.filter_by(email="admin@trustlens.app").first() is None:
        admin = User(name="TrustLens Admin", email="admin@trustlens.app", role="admin")
        admin.set_password("Admin@123456")  # change on first login
        db.session.add(admin)

    if Setting.query.filter_by(key="site_name").first() is None:
        db.session.add_all([
            Setting(key="site_name", value="TrustLens"),
            Setting(key="maintenance_mode", value="off"),
            Setting(key="max_upload_mb", value="16"),
        ])

    # Seed any knowledge items that are not already present (idempotent per-item,
    # so existing databases also pick up newly added evidence on restart).
    existing_claims = {k.claim.lower().strip() for k in KnowledgeItem.query.all()}
    new_items = [KnowledgeItem(claim=c, verdict=v, category=cat, evidence=e, source=s)
                 for c, v, cat, e, s in KNOWLEDGE_SEED
                 if c.lower().strip() not in existing_claims]
    if new_items:
        db.session.add_all(new_items)

    db.session.commit()


# --------------------------------------------------------------------------- #
#  Application factory
# --------------------------------------------------------------------------- #

def create_app(config_class=Config):
    app = Flask(__name__)
    if not os.path.exists(app.instance_path):
     os.makedirs(app.instance_path)
    app.config.from_object(config_class)

    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "warning"

    app.mail = mail  # routes.py accesses app.mail via get_app()

    from routes import register_routes
    register_routes(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    @app.context_processor
    def inject_globals():
        unread = 0
        if current_user.is_authenticated:
            from models import Notification
            unread = Notification.query.filter_by(
                user_id=current_user.id, is_read=False).count()
        return {
            "site_name": Setting.get("site_name", "TrustLens") or "TrustLens",
            "current_year": datetime.now(timezone.utc).year,
            "unread_count": unread,
        }

    # --- Error handlers -----------------------------------------------------
    @app.errorhandler(404)
    def not_found(_e):
        return render_template("404.html"), 404

    @app.errorhandler(413)
    def too_large(_e):
        return redirect(url_for("index"))

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        return render_template("500.html"), 500

       try:
        with app.app_context():
            db.create_all()
            seed_data()
        except Exception as e:
        print(f"Database setup skipped or already initialized: {e}")

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=Config.PORT, debug=Config.DEBUG)
