Used mainly to protect Intellectual Property and other proprietary information an application may contain. Obfuscation can be used to break signatures or prevent program analysis. 
# Structure
To document and organize the variety of obfuscation methods, we can reference this [Research Paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf). It organizes the methods by layers, similar to the OSI model but for application data flow.
![[Pasted image 20240829005135.png]]
Each sublayer is then broken down into specific methods that can achieve the overall objective of the sub-layer. We will be focusing more on the **code-Element Layer** of the taxonomy, as seen in the figure below.
![[Pasted image 20240829005532.png]]
To use the taxonomy, we can determine an objective and then pick a method that fits our requirements. For example, suppose we want to obfuscate the layout of our code but cannot modify the existing code. In that case, we can inject junk code, summarized by the taxonomy: `Code Element Layer` > `Obfuscating Layout` > `Junk Codes`.

# Obfuscation for [[Antivirus#Static Detection|Static Detection]]
AVs and EDRs are one of our biggest obstacles. As they leverage an extensive database of known signatures referred to as static signatures as well as heuristic signatures that consider application behavior.
To evade signatures, adversaries can leverage an extensive range of logic and syntax rules to implement obfuscation. This is commonly achieved by abusing data obfuscation practices that hide important identifiable information in legitimate applications.
These practices can be found under the **Obfuscating Data** sub-layer

| **Obfuscation Method** | **Purpose**                                                        |
| ---------------------- | ------------------------------------------------------------------ |
| Array Transformation   | Transforms an array by splitting, merging, folding, and flattening |
| Data Encoding          | Encodes data with mathematical functions or ciphers                |
| Data Procedurization   | Substitutes static data with procedure calls                       |
| Data Splitting/Merging | Distributes information of one variable into several new variables |

# Object Concatenation
A common concept that combines two separate objects into one. A pre-defined operator defines where the concatenation will occur to combine two independent objects. Depending on the language used in a program there may be different or multiple pre-defined operators that can be used for concatenation. 

| **Language  <br>** | **Concatenation Operator**                       |
| ------------------ | ------------------------------------------------ |
| Python             | “**+**”                                          |
| PowerShell         | “**+**”, ”**,**”, ”**$**”, or no operator at all |
| C#                 | “**+**”, “**String.Join**”, “**String.Concat**”  |
| C                  | “**strcat**”                                     |
| C++                | “**+**”, “**append**”                            |

---

Now, What does that mean for us. Concatenation can open the doors to several vectors to modify signatures or manipulate other aspects of an application. The most common example of concatenation being used in malware is breaking targeted **static signatures**, as covered in [[Signature Evasion|here]]. We can also use it preemptively to break up all objects of a program and attempt to remove all signatures at once without hunting them down, commonly seen in obfuscators.
Here we have a static Yara rule, and we will try to evade it with concatenation
```yara
rule ExmapleRule{
	strings:
		$text_string = "AmsiScanBuffer"
		$hex_string = { B8 57 00 07 80 C3 }
	condition:
		$my_text_string or $my_hex_string
}
```
When a compiled binary is scanned with Yara, it will create a positive alert/detection if the defined string is present. Using concatenation, the string can be functionally the same but it will appear as two independent strings when scanned, resulting in no alerts
```powershell
IntPtr ASBPtr = GetProcAddress(TargetDLL, "Amsi" + "Scan" + "Buffer"); 
```
If this were to be scanned with the Yara rule, there would be no alerts.

---

Extending from concatenation, attackers can also use **non-interpreted characters** to disrupt or confuse a static signature. These can be used independently or with concatenation, depending on the strength/implementation of the signature. Below is a table of some common non-interpreted characters that we can leverage.

| **Character  <br>** | **Purpose  <br>**                                                     | **Example**                 |
| ------------------- | --------------------------------------------------------------------- | --------------------------- |
| Breaks              | Break a single string into multiple sub strings and combine them      | `('co'+'ffe'+'e')`          |
| Reorders            | Reorder a string’s components                                         | `('{1}{0}'-f'ffee','co')`   |
| Whitespace          | Include white space that is not interpreted                           | `.( 'Ne' +'w-Ob' + 'ject')` |
| Ticks               | Include ticks that are not interpreted                                | ``d`own`LoAd`Stri`ng``      |
| Random Case         | Tokens are generally not case sensitive and can be any arbitrary case | `dOwnLoAdsTRing`            |

# Obfuscation for Analysis Deception
After obfuscating basic functions of malicious code, it may be able to pass software detections but is still susceptible to human analysis. While not a security boundary without further policies, analysts and reverse engineers can gain deep insight into the functionality of our malicious application and halt operations. We can leverage advanced login and mathematics to create more complex and harder-to-understand code to combat analysis and reverse engineering.
These are the practices under the **Obfuscating layout** and **Obfuscating controls** sub-layers in [paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf).

| **Obfuscation Method  <br>** | **Purpose**                                                                           |
| ---------------------------- | ------------------------------------------------------------------------------------- |
| Junk Code                    | Add junk instructions that are non-functional, also known as a code stubs             |
| Separation of Related Code   | Separate related codes or instructions to increase difficulty in reading the program  |
| Stripping Redundant Symbols  | Strips symbolic information such as debug information or other symbol tables          |
| Meaningless Identifiers      | Transform a meaningful identifier to something meaningless                            |
| Implicit Controls            | Converts explicit controls instructions to implicit instructions                      |
| Dispatcher-based Controls    | Determines the next block to be executed during the runtime                           |
| Probabilistic Control Flows  | Introduces replications of control flows with the same semantics but different syntax |
| Bogus Control Flows          | Control flows deliberately added to a program but will never be executed              |
## Control Flow and Logic
Control flow is a critical component of a program's execution that will define how a program will logically proceed. Logic is one of the most significant determining factors to an application's control flow and encompasses various uses such as if/else statements or for loops. A program will traditionally execute from the top-down, when a logic statement is encountered, it will continue execution by following the statement.

Now, why is this important. An analyst can attempt to understand a program's function through its control flow, while problematic, logic and control flow is almost effortless to manipulate and make arbitrarily confusing. When dealing with control flow, we aim to introduce enough obscure and arbitrary logic to confuse an analyst but not too much to raise further suspicion or potentially be detected by a platform as malicious

## Arbitrary Control Flow Patterns
We can leverage **predicates** to craft these complex logic and/or mathematical algorithms. Predicates refer to the decision-making of an input function to return true or false. 
Applying this to obfuscation, **opaque predicates** are used to control a known output and input. The paper, [Opaque predicate: Attack and defense in obfuscated binary code](https://etda.libraries.psu.edu/files/final_submissions/17513), states "An opaque predicate is a predicate whose value is known to the obfuscator but is difficult to deduce. It can be seamlessly applied with other obfuscation methods such as junk code to turn reverse engineering attempts into arduous work." Opaque predicates fall under the **bogus control flow** and **probabilistic control flow** methods. They can be used to arbitrarily add logic to a program or refactor the control flow of a pre-existing function.

A common example of an opaque predicate, is the **Collatz conjecture**. It states that if two arithmetic operations are repeated, they will return one from every positive integer. The fact that we know it will always output one for a known input means it is a viable opaque predicate.
```python
x = 0
while(x > 1):
	if(x%2==1):
		x=x*3+1
	else:
		x=x/2
	if(x==1):
		print("proved!") 
```

# Protecting and Striping Identifiable Information
One of the most critical components an analyst can use to dissect and attempt to understand a malicious program. By limiting the amount of identifiable information (variables, functions names, etc.) an analyst has, the better chance an attacker has they won't be able to reconstruct its original function.
At high level, we should consider three different types of identifiable data, Code structure, object names, and file/compilation properties. 
## Object names
Object names offer some of the most significant insight into a program's functionality and can reveal the exact purpose of a function. An analyst can still deconstruct the purpose of a function from its behavior, but this is much harder if there is no context to the function.
The importance of literal object names may change depending on if the language is **compiled** or **interpreted**. If an interpreted language such as Python or PowerShell is used, then all objects matter and must be modified. If a compiled language such as C or C# is used, only objects appearing in the strings are generally significant. An object may appear in the strings by any function that produces an IO operation.
These practices are found under the **meaningless identifiers** method in the [paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf).

## Code structure
Code structure can be a bothersome problem when dealing with all aspects of malicious code that are often overlooked and not easily identified. If not adequately addressed in both interpreted and compiled languages, it can lead to signatures or easier reverse engineering from an analyst.
Just like [paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf) says, **Junk code** and **reordering code** are both widely used as additional measures to add complexity to an interpreted program. Because the program is not compiled, an analyst has much greater insight into the program, and if not artificially inflated with complexity, they can focus on the exact malicious functions of an application.
Separation of related code can impact both interpreted and compiled languages and result in hidden signatures that may be hard to identify. A heuristic signature engine may determine whether a program is malicious based on the surrounding functions or API calls. To circumvent these signatures, an attacker can randomize the occurrence of related code to fool the engine into believing it is a safe call or function.

## File/Compilation properties
More minor aspects of a compiled binary, such as the compilation method, may not seem like a critical component, but they can lead to several advantages to assist an analyst. For example, if a program is compiled as a debug build, an analyst can obtain all the available global variables and other program information.
The compiler will include a symbol file when a program is compiled as a debug build. Symbols commonly aid in debugging a binary image and can contain global and local variables, function names, and entry points. We must be aware of these possible problems to ensure proper compilation practices and that no information is leaked to an analyst.
Luckily for us, symbol files are easily removed through the compiler of after compilation. To remove symbols from a compiled like **Visual Studio**, we need to change the compilation target from `Debug` to `Release` or use a lighter-weight compiler like **mingw**.
If we need to remove symbols from a pre-compiled image, we can use the command-line utility: `strip`
These practices can be found in [paper](https://cybersecurity.springeropen.com/track/pdf/10.1186/s42400-020-00049-3.pdf), under the **stripping redundant symbols** method
