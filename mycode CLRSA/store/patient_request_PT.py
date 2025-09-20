# patient_request_AT.py (RSA)

import json
import hashlib
import requests
import random
from sympy import mod_inverse as sympy_mod_inverse
from sympy import mod_inverse

from bplib.bp import BpGroup
from petlib.pack import encode, decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from petlib.bn import Bn
import hashlib
import json


n = 3839514345387410341423022334927189038634447016638837295033434667390789128372002206607351703997416831510199857890468938575112370145062730949064523058143131785479044281363019265694762100658698854299808954919854105518894694968662003390830447279926968144971289701239649573922706150830571090915654607491401127409249862667795578589532425982174437056981110499101593439616092595937018411712430485745028190239817713161876784875118039784829208417592536161434645857962093138993032093338095538038483715407550907439160658119295194071632592301734414971054550181766789371357507306967888454558151389948291730865474982106305463843997809395621723954587775109360748419318767802360259649195872369170513115889098664112709091426646947209181199849354139601061745706236776688203174170329312252949719962410918717528223157772941379515571230726974341634948998830685959576000835092469175311650252494295113829438877679689959647984237381769781161402492687
phi_n = 3839514345387410341423022334927189038634447016638837295033434667390789128372002206607351703997416831510199857890468938575112370145062730949064523058143131785479044281363019265694762100658698854299808954919854105518894694968662003390830447279926968144971289701239649573922706150830571090915654607491401127409249862667795578589532425982174437056981110499101593439616092595937018411712430485745028190239817713161876784875118039784829208417592536161434645857962093135041061371410628565170929368191049782530173439695665537036992655983861049560388966203191509918602711637052081738445248684837076977580608783171016419354355553468876081993693450626941214780475713593036008541027938541080697368756090655158173344212706814864725456050566135338452524415147150652792145172980439281617366231821350131691449924046475571797564959611226440984745527396551868768110254866715072767875278672189261218287834865184201833807294725304540043631944976
e = 65537
d = 1370840840559073722919225774981480634069417668528192530425367926244366919675549378708293368964639157125092184182661438480843711934087963157867476006492380497252302625076114069884061497983015617006595201735960849825848253163430157275158179896898105308820715133730664515925620660440431099323060289007603261977951958993602831124654305744188773558391458329927799333103086052952229943629692554373070397232425876531955305999555777849538713211823058022817786569883501186609484642715371435928324096103000959174565944663913177306385570858696075478943824407410747220430975625911800366173007216938565454604401558164374524260685804898274737058004379987179722670374768792643080456101328012004626969979153230084472863897235557944668064545633718369538590701283674536897987471238678895136560301179299811273757370229999571303099355935472900691244039177135315582114101250076536730328114586425324980495247692302747130769746696940673703113415025
# n bit length = 3072

# Issuer's Public Key Components:
R_values = [2197917715551317901390630523182966687613536696635569358583392315346089545171696976456428536907830941881945887892107834372220004431262416980922381881738534890248633617838530949094573217891586082423970410467389012943528974620419282707129769822822476934672972217548071515103985216010407305131555317342870259767340389512776990608075721501455594865461475908919508704238425389100958599670473062523837753052036137209247530382055796525017304703882627937881924498545161288958898526481867016872035040627029312941747958293720380884438583318880690689559841137254372147403336415145273266286312615408027304523668469500076996380046117795630097884140766448835012106419232936022274376121954496710418468430594284963856798103666602659806750368750549200835778722131241488166997501232105360432504497165612449668866461957815260456376819314942207208775423414339467566032820722251697870370215120842482224739063646924795505971094333647559622830185710, 3380937750991516271603253300470664540550298342041923386895520749703766788746769214820446007627874528001804385898418498069629662501798003438520533958032729462348371094272972929212286013792762293644890798134332510271809866973878782337280909321031467927520502195914514981477513219137239387202804013058128840207328694799663567487920169591537850881813086750473941958504515125542144100337294400547965111423401564471733255772882852611677082493727989138527088107000303467885180984961069942960271589754162965199308121055778082410155865299118153194634596275363173944297969884511473089824318512979487918820532979341488433458211696740795775031690721738381780577394660834266574934759550189972880107884060301515806274958278134068250615715117760554123562312147315058322078641495376399894417451849607049133810330273713559583780065691964067021773634572053429397985233521902179995145356560120901535086775784741418123113105472716571160385569268, 1447950163390734906649565412177841649681152371109699849506512103152123708269325702566750089349585425441413068574024188201103016578001943290464588225045018560896897930247409180172138496641253786756431639830515594169960296293330915700337917254186391080802312253317356506027108915603183820686043494886557850851328122769087984875635947759158745281067513985780571546466111040541797775805814437642346829260739001021106270786696704707130749398697027639873111604004024163371207716358660213535198380090930368838092370325514880689376866554041527359251566418392211425237317285746228700082379843133297018015528161704761397570996415089706265193229935820190677452561484817517820016830438768395344956942621946447174114207902571100395629830290378650400229302934417314531914226979890756241837839353140674414432286611547294836547316235537764684155849028768606962167049073942248588538842803823927227913043682079387546070047922372445147108778663, 1585128954903010492324234322289528701545587419102648938382019722538118117366256020650599401435055781355140854571293118977767389240979032444142543060201885019475205642387402348629621228252443410948926905583710928993458679224744279733044876550820324888518718984444131576703201241130132086459684441693778507766587400350879846122478822697513439250985151204479434087449742461230556130866463329628021308253170791073957969623679023480953849978028711988302053826646801565541397158283278198425047595803106212190349809972277598389939426884355544455639423957884718243588705015456363661297604415960751147305039969251593237995980477995219862610478051080921003014703497776282831542601692990384080777769986147261311222434249018688390716961944443038463430218413267534253072437235101552755358727791970089462439157562998456284027601900101282452362986734034125467933611252175688536334341723136013299566768303623363091480659299300181620398884030, 3466479517466151609328645223858831342749629474547484282791771367174973868897303485055749166632969055447350718747656757316853823436099945140874479267636552103687093208419732028190182937736791022924396159826289720098546196994505412221328957799311632229351684325053356292405140609680720671280094048303842161668461873065114950718272907516596322208631320948909942215927277426087371063160567714481544538646635461219084433379653991489285328478830314072453698455041654056587322807351148409019412606298531190956928189599974991353959914259259901685949623144829042197799578513817154191785648789656334556447707238968051406407108132729525174753376091635939986764052407604074925165351219279997180509653808731877390973203251758295977014649078590053014990624202752013567894792931687644485634882707226417207233023563733376291782660419622362672043045939504672488977273926078428916708904488771414008634312873716136242607895475353677795122621955, 3266378199924096991314936362946511734816266242578152965732255342339150813863655940370992607472514701547833846745824611650562764418672097010581841308092272219554901499381364248273623821263010735245598461689204992932669171932728231006886657561855122784643413082754917680954273472511809967246041682775739445062096679384974844042704632306636062198359854911750702812430163260353927688697204429721324853151106444971794964479910146456580234093548473145326760318715232937097790886919696648214240154917858203851667105311698798078423818158989688919219599049885254255565605366601996383347654038156499264777785009352905155107612227006668207496637763158638213679116314729629504546124783439649206582237018090052173847416061302399576311283494350942136664270079107154063708493279141566647813455576569113882316695557820003616762197767086181091566771316767305464979702718677483839669251118986245221810216719196746974553912205192905531048811275, 1362516454171862826465423940007896745693942465836212912259096452801385357483109712533090273858627473276792423646168239374831207459714374893310862324474367542641823781738344444116393727063189179472565092954132209159796440144240841023171099496524446745050047978595326525375739929319395201764313796060257118853114314110276542959550957977345721046754230110666663465871578656524730991644970323161721628016049727117928436297167284161063462291108040794349238015532904048658608346817527962862062460338058948954507464173945950282061218218196680753023059654443613682648353967386868148713237349056062422059620258562332156878748202134846170517174264178514685735648199564309847455934723983715618575511831572041018598725656464141672999755341954193198575801997732879424977387817647116886285977533310699845898033600127878728576045632997623408121259750361469100204362846451239718806829920667496051928071046475498646793163405578849223623711766, 1067762353383580551135839014404432778344245015772335522559661715077801215059259278998279021636141661267632046925627500932847877616603353399832051093575796753805216641721588507051916475065653434620372212575320083795000187190904597691267095148235681925571905202830871679851700909766689440522456640046283108306570546062322346597875032192151434600126190670540359054192048253454340346668001208481186360502295474903333744646065148044584203676525446559706906152629616261075442944713852170654839314000690403214745356975119453678049008961017023224480790774477932824777461739944610658188254616612303815153390608747991551205368461250073829421863420451485531060826807431483884155896119735028409616392162307393606130402295707351555020256436469766032404316910741523128005579634432571993126390853769433951171869680992323575278807076884287865718220148569528293701526932913887662218970560563575010365374400226657905762528657092783512158079230]
S = 3158877261747170227933171765036871433528512321055490196212967910318364429646062209857521876916159557930129666655109071581698487586878015465613496362339412808850434587376781102577974794286733759481375156574287647473082951387816578331687106875169702351551995520805745168930403499172063949372632492303144039069924603281508438730408368910788768095565712914611942411213913097290613890173603641720764115352166209518815903776983270259895622484299690592428828513437436815921849045735336294064710569982102286369754581315446301346887738578231305312868190511307997323056205759476429099941563215803677441929342373135391313546569967901805654730949504685443085171970441739975056366141584394100254156529267108058381582132673754813129499207226560385582262281142698902507235730641377755888378856612265592855491633033814761287243030204157967413609296446891115735862475292648665049897146958510743515147946646408502534215651274479135529306257204
Z = 1081847561503614272019698987802918901137595129351720364543455604029614896648566550836917485704538442467570516045692696144737938842749008959325067689870563313839984366166118876831696312585734213889755949188135187917936951033543886754861340936771635861515936061706288007650554150369141787834615665285804082646635824771996161904456944241001513318199687005192535736051856002105966143542941009232766063769796559089719460799471103107003922910401123054792207033403208326640601265026256758084756892550015453298865296389457009828368296193555006503431951620666185283956945626532174848890463247972476986883005451281072248820578712644887029173140043463515344178248729326906730932322425955019787355952121905343578172245117383258153613757094546229819597449535777131287581512840134860182852195520487297754187988870638571006645244124737391599159048741641862862745162646724263928251807438191257416872012522546978290241019498037556203771438663

# Random Values:
v = 654671824456777219652346992867510087452212166114968701545910942952091121622112746156990349070961452148860376720831950798312197450766246824784080733014046252963734155048583326731280382293616188983912637757247490994134629330532195580185840805308883310892596697184472355715553141495826312755328377140784745150265379895750720993018126057154831983174916794530919730650307200963941003018876409147386940897668082078766480477827328301029796277743754598293877575928072808973258839963503463480166821397108546716171125444499692569916119887969930293047808484483273731991341192429839395439534141080457006319937166802684530909784068883785506166993489700586680366768423556053862169783609543635311890846239387114538930159414622420235484998108726586641428521794864504382328757606950689879098678386420605325447766876632966595473475790750546381184756393588593932117938456568203825601986951442140336748646534884150544366919313446605434742292492
r = 3049937574555449399620115139050483235536535269458720093879241714475985644286784305930376419269591571692860672771237159858248112691075420677785965568027919218957173979090956738445837898005526235497303005338345543435910569889677149992957408113869404430878685522531254808371205526376368096602715542178562090721428412515988076310933307649707847331395058812845158162107795726601894194689598822186522538852013424191712716605670775475208908827300854791096866464490645549565329498734920345592045558057664021486623394952966844538107254087646800330136844582199535838433822537938085201500518144608094217176125788879495030448298666637849627971813879060239531645892709088857251471775727616635752937355832238024126655208046939174402585015628995398160507003862768827690362163546223701510108544156309227783494295826521029789617185728864165753519745882612493419788785649606663280096250258108800499884145638256151316593610811365436767366774647

# R0 is the first element in R_values, and R1 to R6 are the subsequent elements
R0 = R_values[0]  # R0 for the user's secret key
R_attributes = R_values[1:]  # R1 to R6 for attributes /*important*/

# Patient credential order
Patient_credential_ORDER = ['credential_id', 'did_patient', 'patient_id', 'biometric_data', 'issue_date', 'did_apc']


# User's private key
sk_user = 17304765680399877985603549156602165040317349863534909960824703260664115188005314383251413388475509418285750437797512658247933731564609469620976572906899147469047469887962579684739486778701980430346446321047488914359791851791139784526292922401723187689749972813113085232791979266364003313836365197957166825071559991192573379064100196327396995359152684197702309998257340184443026266288319011820495800045861852371823748758949393171374448839279286169397125792444022976661238526330260402304122797946075324472645068283108408038784858222678196156475420470935657199584768392650117759440320863062033482833553787859584529184659
pk_user = pow(R0, sk_user, n)

print("User's private key:", sk_user)
print("User's public key:", pk_user) 



# 
# Initialize pairing group (default BN254)
group = BpGroup()


# --- Public Parameters ---
g1 = group.gen1()
g2 = group.gen2()
z = group.pair(g1, g2)

# --- Key Generation ---
sk_patient = group.order().random()
pk_patient = g2 * sk_patient

sk_HRR = group.order().random()
pk_HRR = g1 * sk_HRR


# Define discrete log group parameters for Schnorr signature
p1 = 162259276829213363391578010288127  # A large prime number
q1 = 81129638414606681695789005144063   # A prime divisor of p1 - 1
g1_schnorr = 2  # Generator for the subgroup of order q1

# Generate Schnorr signing key pair (PT)
x_sign = 563452374  # Private key (example)               PT
Y_sign = pow(g1_schnorr, x_sign, p1)  # Public key        PT


# ==============================================================================
# 3. NIZK PROOF IMPLEMENTATION (APPENDIX A)
# ==============================================================================

def generate_binding_proof(P_patient_a, P_patient_b, r, pk_patient, patient_id_str):
    """
    Generates a NIZK proof for binding the patient credential and pseudonym.
    """
    print("\n--- Generating NIZK Binding Proof (Patient's Side) ---")

    # 1. Choose random scalars t1, t2
    t1 = group.order().random()
    t2 = group.order().random()

    # 2. Compute commitments T1 (in GT) and T2 (in G2)
    T1 = z ** t1
    T2 = pk_patient * t2
    print("Step 1 & 2: Commitments T1, T2 generated.")

    # 3. Compute Fiat-Shamir challenge 'c'
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()

    hasher = hashlib.sha256()
    hasher.update(encode(P_patient_a))
    hasher.update(encode(P_patient_b))
    hasher.update(encode(T1))
    hasher.update(encode(T2))
    hasher.update(encode(pk_patient))
    hasher.update(encode(patient_id_fr))
    
    c = Bn.from_hex(hasher.hexdigest()) % group.order()
    print(f"Step 3: Fiat-Shamir Challenge 'c' computed.")

    # 4. Compute responses s1, s2
    s1 = (t1 + c * r) % group.order()
    s2 = (t2 + c * r) % group.order()
    print("Step 4: Responses 's1' and 's2' computed.")

    # 5. Assemble the final proof
    proof = {
        "T1": group_element_to_hex(T1),
        "T2": group_element_to_hex(T2),
        "c": c.hex(),
        "s1": s1.hex(),
        "s2": s2.hex()
    }
    
    print("Step 5: NIZK Proof generated successfully.")
    return proof

def verify_binding_proof(proof, P_patient_a, P_patient_b, pk_patient, patient_id_str):
    """
    Verifies the NIZK proof of binding.
    """
    print("\n--- Verifying NIZK Binding Proof (PTA's Side) ---")

    # Unpack the proof components
    T1 = hex_to_group_element(proof['T1'])
    T2 = hex_to_group_element(proof['T2'])
    c = Bn.from_hex(proof['c'])
    s1 = Bn.from_hex(proof['s1'])
    s2 = Bn.from_hex(proof['s2'])

    # Recompute Hash(PatientID)
    patient_id_fr = Bn.from_hex(hashlib.sha256(patient_id_str.encode()).hexdigest()) % group.order()
    
    # -- Verification Equation 1 (in GT, multiplicative) --
    print("Verifying Equation 1...")
    lhs1 = z ** s1
    patient_id_gt = z ** patient_id_fr
    p1_div_hash = P_patient_a * (patient_id_gt ** -1) 
    rhs1 = T1 * (p1_div_hash ** c)
    check1 = (lhs1 == rhs1)
    print(f"Verification Check 1 (in GT): {'PASSED' if check1 else 'FAILED'}")

    # -- Verification Equation 2 (in G2, additive) --
    print("Verifying Equation 2...")
    lhs2 = pk_patient * s2
    rhs2 = T2 + (P_patient_b * c)
    check2 = (lhs2 == rhs2)
    print(f"Verification Check 2 (in G2): {'PASSED' if check2 else 'FAILED'}")
    
    return check1 and check2
 


###
def schnorr_signature_generate(pseudonym_token_bytes, x_sign):
    """
    Generate a Schnorr signature using the finite field parameters.
    """
    r = 123456789  # Example fixed random nonce for testing
    R = pow(g1_schnorr, r, p1)  # Compute R = g^r mod p

    # Compute the challenge
    h = hashlib.sha256()
    h.update(R.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c = int.from_bytes(h.digest(), 'big') % q1

    # Compute the signature component s
    s = (r - c * x_sign) % q1

    return s, c  # Return signature (s, c)


def schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign):
    """
    Verify a Schnorr signature.
    """
    R_prime = (pow(g1_schnorr, s, p1) * pow(Y_sign, c, p1)) % p1  # R' = g^s * Y^c mod p

    # Compute the hash challenge
    h = hashlib.sha256()
    h.update(R_prime.to_bytes((p1.bit_length() + 7) // 8, 'big') + pseudonym_token_bytes)
    c_prime = int.from_bytes(h.digest(), 'big') % q1

    # Check if the computed c_prime matches the original c
    return c_prime == c


###
 # Function to hash and reduce an attribute
def hash_and_reduce(attribute, n):
    attribute_hash = hashlib.sha256(attribute.encode()).hexdigest()
    attribute_int = int(attribute_hash, 16)
    return attribute_int % n


# Function to verify the proof of knowledge of the user's patient id
def verify_proof_of_knowledge_patient_id(proof_of_knowledge_verification_parameters):
    print("Verifying proof of knowledge...")

    # Extract parameters from the proof of knowledge structure
    A_prime = proof_of_knowledge_verification_parameters['A_prime']
    Z_tilde = proof_of_knowledge_verification_parameters['Z_tilde']
    c = proof_of_knowledge_verification_parameters['c']
    e_hat = proof_of_knowledge_verification_parameters['e_hat']
    v_hat = proof_of_knowledge_verification_parameters['v_hat']
    sk_user_hat = proof_of_knowledge_verification_parameters['sk_user_hat']
    m_hat = proof_of_knowledge_verification_parameters['m_hat']
    disclosed_attributes = proof_of_knowledge_verification_parameters['disclosed_attributes']
    nonce = proof_of_knowledge_verification_parameters['nonce']
    
    print(f"Received from patient: A_prime={A_prime}, Z_tilde={Z_tilde}, c={c}, e_hat={e_hat}, v_hat={v_hat}, sk_user_hat={sk_user_hat}, m_hat={m_hat}, disclosed_attributes={disclosed_attributes}, nonce={nonce}")

    # Determine the disclosed and hidden indices based on disclosed_attributes
    disclosed_indices = []
    hidden_indices = []
    for idx, attr in enumerate(Patient_credential_ORDER):
        if attr in disclosed_attributes:
            disclosed_indices.append(idx)
        else:
            hidden_indices.append(idx)
    
    print("Disclosed indices:", disclosed_indices)
    print("Hidden indices:", hidden_indices)

    # Compute modular inverse of Z
    try:
        Z_inv = sympy_mod_inverse(Z, n)  # Z_inv = Z^{-1} mod n
    except ValueError:
        print("Modular inverse does not exist for Z and n.")
        return False  # Verification fails if modular inverse doesn't exist

    # Compute Z^{-c} mod n
    Z_inv_c = pow(Z_inv, c, n)  # Z_inv_c = Z_inv^{c} (mod n)

    # Calculate various terms for the verification
    A_e_hat = pow(A_prime, e_hat, n)  # A_e_hat = A_prime^{e_hat} mod n
    S_v_hat = pow(S, v_hat, n)        # S_v_hat = S^{v_hat} mod n
    R0_sk_hat = pow(R0, sk_user_hat, n)  # R0_sk_hat = R0^{sk_user_hat} mod n

    # Compute Z_hat as the accumulated product
    Z_hat = (Z_inv_c * A_e_hat * S_v_hat * R0_sk_hat) % n

    # For disclosed attributes, compute R_i^{c * m_i} mod n using known values
    m = {}
    for idx, value in zip(disclosed_indices, disclosed_attributes.values()):
        attribute_value = hash_and_reduce(value, n)
        m[idx] = attribute_value

    print("attribute_value 🔥: ", attribute_value)
    print ("m (disclosed attributes) 🔥:", m)

    # Multiply disclosed attribute components into Z_hat
    for idx in disclosed_indices:
        R_i = R_attributes[idx]
        Z_hat = (Z_hat * pow(R_i, c * m[idx], n)) % n  # Z_hat = Z_hat * R_i^{c * m_i} mod n
    
    # For hidden attributes, use the provided m_hat values
    for idx in hidden_indices:
        R_i = R_attributes[idx]
        if idx in m_hat:  # <-- FIXED: use integer key
            Z_hat = (Z_hat * pow(R_i, m_hat[idx], n)) % n
        else:
            print(f"Missing m_hat value for hidden attribute index {idx}")
            return False

    print("Z_hat (recomputed):", Z_hat)
    print("Z_tilde (original):", Z_tilde)

    # Recompute the challenge c_prime
    data_to_hash_verification = str(A_prime) + str(Z_hat) + str(nonce)
    c_prime = int(hashlib.sha256(data_to_hash_verification.encode()).hexdigest(), 16)

    print("Original c:", c)
    print("Recomputed c_prime:", c_prime)

    # Check if the recomputed challenge matches the original challenge
    if c_prime == c:
        print("Proof is valid!")
        return True
    else:
        print("Proof is invalid!")
        return False



# Generate of proof of knowledge of the user' patient id of the patient credential
# File path of the JSON file
file_path = r"/home/nmuslim162022/Desktop/mycode/patient_credential_signature.json"

# Load the JSON file
with open(file_path, 'r') as file:
    patient_credential = json.load(file)

# Print the loaded data
print(patient_credential)

# Map patient attributes to m_i
attribute_values = []
for value in patient_credential['info'].values():
    attribute_value = hash_and_reduce(value, n)
    attribute_values.append(attribute_value)

print ("Attribute Values: ", attribute_values)

# Calculation of R_m
R_m = 1
for i, attr_value in enumerate(attribute_values):
    R_m = (R_m * pow(R_attributes[i], attr_value, n)) % n
print("R_m: ", R_m)    

R = (R_m * pk_user) % n
print("R$: ", R)

print ("Patient Credential signature parameters: ")
print( "A: ", patient_credential['signature']['A'] )
print( "e: ", patient_credential['signature']['e'] )
print( "v: ", patient_credential['signature']['v'] )

S_r = pow(S, r, n)             # Compute S^r mod n
S_r_inv = mod_inverse(S_r, n)  # compute S^(-r)  mod n
A_prime = (patient_credential['signature']['A'] * S_r_inv) % n    # Compute A * S^(-r) mod n
v_prime = (v + patient_credential['signature']['e'] * r)          # Compute v' = v + e*r

Z_prime = ( pow(A_prime, patient_credential['signature']['e'], n) * pow(S, v_prime, n) * R) % n # Compute Z' = A'^e * S^v' * R mod n
print ("Z_prime: ", Z_prime)

# user's disclosed attributes
disclosed_attributes = {
    'patient_id': patient_credential['info']['patient_id'],
}

print ('disclosed_attributes 🦊: ', disclosed_attributes)
patient_id = patient_credential['info']['patient_id']


# Map patient attributes to m_i based on patient_credential
m = []
for key, value in patient_credential['info'].items():
    print('key:', key)
    attribute_value = hash_and_reduce(value, n)
    m.append(attribute_value)
    print(f"value*: {value}, attribute_value: {attribute_value}")

# Fixed random values for debugging
e_tilde = 71283868338990786193364740118650178393         # Random value for e'
v_tilde = 234672227276554471863123710545218028003        # Random value for v'
sk_user_tilde = 213712384778698537675704610942567300823  # Random value for user's secret key
nonce = 237133831923579981081203483126789063270          # Random nonce value


# selection of the disclosed and hidden attributes 🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥🔥
disclosed_indices = [2]        # Indices of disclosed attributes m[0] and m[1]
hidden_indices = [0, 1, 3, 4, 5]     # Indices of hidden attributes m[2] and m[3]

m_i_tilde = {0: 114096786540045931831531287662410155747, 1: 336880516579979780763399956619176063555, 3: 134364043404748232386372829164288157778, 4: 289347234987234987234987234987234987234 , 5: 198234987234987234987234987234987234987 }  # Fixed random values for hidden messages


# Initial Z_tilde calculation including pk_user
Z_tilde = (pow(A_prime, e_tilde, n) * pow(S, v_tilde, n) * pow(R0, sk_user_tilde, n)) % n # Z_tilde = A_prime^{e_tilde} * S^{v_tilde} * R0^{sk_user_tilde} mod n


# Incorporate hidden attributes into Z_tilde
for idx in hidden_indices:
    R_i = R_attributes[idx]
    Z_tilde = (Z_tilde * pow(R_i, m_i_tilde[idx], n)) % n # Z_tilde = Z_tilde * R_i^{m_i_tilde} mod n

print("Z_tilde: ", Z_tilde)

# Calculate the challenge c using hash
data_to_hash = str(A_prime) + str(Z_tilde) + str(nonce)  
c = int(hashlib.sha256(data_to_hash.encode()).hexdigest(), 16) # c = H(A_prime, Z_tilde, nonce) 

# Update e_hat and v_hat
e_hat = e_tilde + c * patient_credential['signature']['e']                   # e_hat = e_tilde + c * e
v_hat = v_tilde + c * v_prime             # v_hat = v_tilde + c * v_prime
sk_user_hat = sk_user_tilde + c * sk_user # sk_user_hat = sk_user_tilde + c * sk_user



# Calculate m_hat for hidden attributes
m_hat = {}
for idx in hidden_indices:
    m_hat[idx] = m_i_tilde[idx] + c * m[idx] # m_hat = m_i_tilde + c * m_i

print("e_hat🌱: ", e_hat)
print("v_hat🌱: ", v_hat)
print("sk_user_hat🌱: ", sk_user_hat)
print("m_hat🌱: ", m_hat)

proof_of_knowledge_patient_credential_verification_parameters = {
    'A_prime': A_prime,
    'Z_tilde': Z_tilde,
    'c': c,
    'e_hat': e_hat,
    'v_hat': v_hat,
    'sk_user_hat': sk_user_hat,
    'm_hat': m_hat,
    'disclosed_attributes': disclosed_attributes,
    'nonce': nonce
}


# Print the proof of knowledge verification parameters
print("proof_of_knowledge_verification_parameters *: ", proof_of_knowledge_patient_credential_verification_parameters)


###
file_path = "/home/nmuslim162022/Desktop/mycode/patient_pseudonym_data.json"

# Read JSON data from file    
def read_json_file(file_path):
    with open(file_path, "r") as json_file:
        return json.load(json_file)
    

# Serialization and Deserialization
def group_element_to_hex(element):
    """Serialize a group element and convert it to a hex string."""
    return encode(element).hex()

def hex_to_group_element(hex_str, group):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)   

# --- Deserialization and Preparation for NIZK Proof ---

# The hex_to_group_element function doesn't need the 'group' argument
# because petlib's decode is smart enough.
def hex_to_group_element(hex_str):
    """Deserialize a group element from a hex string."""
    element_bytes = bytes.fromhex(hex_str)
    return decode(element_bytes)


pseudonym_data = read_json_file(file_path)
print ("pseudonym_data: ", pseudonym_data)



# Convert hex strings to cryptographic objects
P_patient_a = hex_to_group_element(pseudonym_data['P_patient_a'])
P_patient_b = hex_to_group_element(pseudonym_data['P_patient_b'])
rk_patient_to_HRR = hex_to_group_element(pseudonym_data['rk_patient_to_HRR'])
encrypted_pid = bytes.fromhex(pseudonym_data['encrypted_pid'])

# THIS IS THE KEY FIX: Load the correct 'r' and convert it to a Bn object
r_nizk = Bn.from_hex(pseudonym_data['r'])
# Also load the matching public key and patient ID
pk_patient_nizk = hex_to_group_element(pseudonym_data['pk_patient'])
patient_id_nizk = pseudonym_data.get('patient_id', patient_id) # Use loaded ID for consistency

# --- NIZK Proof Generation (Patient's Side) ---
# The patient uses the loaded pseudonym and the CORRECT secret 'r' to generate the proof
binding_proof = generate_binding_proof(
    P_patient_a, P_patient_b, r_nizk, pk_patient_nizk, patient_id_nizk
)

# Prepare the request to the APC server (appointment_token_id and proof_of_knowledge_verification_parameters) 
data = {
    'pseudonym_data': pseudonym_data,
    'binding_proof': binding_proof,
    'proof_of_knowledge_patient_credential_verification_parameters': proof_of_knowledge_patient_credential_verification_parameters
}



#####################################################
#####################################################

# Send the request to the APC server
if not verify_proof_of_knowledge_patient_id(proof_of_knowledge_patient_credential_verification_parameters):
    print("Proof of knowledge verification failed.")
   

print ("pseudonym_data: ", pseudonym_data)

# Prepare the pseudonym token as a concatenated byte string for verification
pseudonym_token_bytes = (
    bytes.fromhex(group_element_to_hex(P_patient_a)) +
    bytes.fromhex(group_element_to_hex(P_patient_b)) +
    bytes.fromhex(group_element_to_hex(rk_patient_to_HRR)) +
    bytes.fromhex(encrypted_pid.hex())
)


# --- NIZK Proof Verification (PTA's Side) ---
# The PTA receives the pseudonym and the newly generated proof.
# It MUST use the same public key and patient ID that were used in the proof generation.
is_valid = verify_binding_proof(
    binding_proof, P_patient_a, P_patient_b, pk_patient_nizk, patient_id_nizk
)
    
print("\n--- Final Result ---")
if is_valid:
    print("✅ The NIZK proof is VALID. The PTA can trust the binding between the pseudonym and the PatientID.")
else:
    print("❌ The NIZK proof is INVALID. The request should be rejected.")
    


# Generate Schnorr signature
s, c = schnorr_signature_generate(pseudonym_token_bytes, x_sign)
print("\nSignature generated:")
print("s:", s)
print("c:", c)
print("Y_sign:", Y_sign)

# Serialize and store data
data_to_store = {

    "info": {
        "P_patient_a": group_element_to_hex(P_patient_a),
        "P_patient_b": group_element_to_hex(P_patient_b),
        "rk_patient_to_HRR": group_element_to_hex(rk_patient_to_HRR),
        "encrypted_pid": encrypted_pid.hex()
        },
    "signature": {
        "c": c,
        "s": s,
        "Y_sign": Y_sign  # Directly convert Y_sign to hex since it's an integer
        }
    }


# Save (optional)
with open("/home/nmuslim162022/Desktop/mycode/signed_pseudonym_token.json", "w") as f:
    json.dump(data_to_store, f, indent=2)


pseudonym_token_bytes = (
    bytes.fromhex(group_element_to_hex(P_patient_a)) +
    bytes.fromhex(group_element_to_hex(P_patient_b)) +
    bytes.fromhex(group_element_to_hex(rk_patient_to_HRR)) +
    bytes.fromhex(encrypted_pid.hex())
)

# --- Example Verification ---
valid = schnorr_signature_verify(pseudonym_token_bytes, s, c, Y_sign)
print("\nSignature valid:", valid)