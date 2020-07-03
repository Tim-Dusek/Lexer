import java.io.*;
import java.util.*;
import java.util.regex.*;

public class Lexer {
	
	public static void getsym(String input, PrintWriter p, int lineCounter){
		input = input.trim();
		
		if (input.matches("^\\(\\*.*")){ //Ignores comments by cheking the (* comment symbol
			
			return;
		}
		
		else if (input.matches("")){ //goes to the next line if line is empty
			
			return;
		}
		//Start of reserved word portion (in order from class handout, almost)
		else if (input.matches("(?i)^and.*")){
			int offset=0;
			String REGEX = "(?i)^and";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "andsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^array.*")){
			int offset=0;
			String REGEX = "(?i)^array";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "arraysym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^begin.*")){
			int offset=0;
			String REGEX = "(?i)^begin";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "beginsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^char.*")){
			int offset=0;
			String REGEX = "(?i)^char";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "charsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^chr.*")){
			int offset=0;
			String REGEX = "(?i)^chr";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "chrsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^div.*")){
			int offset=0;
			String REGEX = "(?i)^div";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "divsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^do.*")){
			int offset=0;
			String REGEX = "(?i)^do";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "dosym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^else.*")){
			int offset=0;
			String REGEX = "(?i)^else";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "elsesym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^end.*")){
			int offset=0;
			String REGEX = "(?i)^end";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "endsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^if.*")){
			int offset=0;
			String REGEX = "(?i)^if";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "ifsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^integer.*")){
			int offset=0;
			String REGEX = "(?i)^integer";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "integersym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^mod.*")){
			int offset=0;
			String REGEX = "(?i)^mod";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "modsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^not.*")){
			int offset=0;
			String REGEX = "(?i)^not";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "notsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^of.*")){
			int offset=0;
			String REGEX = "(?i)^of";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "ofsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^ord.*")){
			int offset=0;
			String REGEX = "(?i)^ord";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "ordsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^or.*")){
			int offset=0;
			String REGEX = "(?i)^or";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "orsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^procedure.*")){
			int offset=0;
			String REGEX = "(?i)^procedure";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "proceduresym", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^program.*")){
			int offset=0;
			String REGEX = "(?i)^program";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "programsym", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^readln.*")){
			int offset=0;
			String REGEX = "(?i)^readln";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "readlnsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^read.*")){
			int offset=0;
			String REGEX = "(?i)^read";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "readsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^then.*")){
			int offset=0;
			String REGEX = "(?i)^then";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "thensym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^var.*")){
			int offset=0;
			String REGEX = "(?i)^var";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "varsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^while.*")){
			int offset=0;
			String REGEX = "(?i)^while";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "whilesym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^writeln.*")){
			int offset=0;
			String REGEX = "(?i)^writeln";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "writelnsym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^write.*")){
			int offset=0;
			String REGEX = "(?i)^write";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "writesym", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^function.*")){
			int offset=0;
			String REGEX = "(?i)^function";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "functionsym", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		//This is the start of matching the reserved signs, such as + and *
		
		else if (input.matches("(?i)^\\+.*")){
			int offset=0;
			String REGEX = "(?i)^\\+";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "plus", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^-.*")){
			int offset=0;
			String REGEX = "(?i)^-";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "minus", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\*.*")){
			int offset=0;
			String REGEX = "(?i)^\\*";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "times", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^<=.*")){
			int offset=0;
			String REGEX = "(?i)^<=";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "lessequal", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^<>.*")){
			int offset=0;
			String REGEX = "(?i)^<>";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "notequal", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^>=.*")){
			int offset=0;
			String REGEX = "(?i)^>=";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "greaterequal", chomp.substring(0,offset)); //print the token name
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^<.*")){
			int offset=0;
			String REGEX = "(?i)^<";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "less", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^>.*")){
			int offset=0;
			String REGEX = "(?i)^>";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "greater", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^=.*")){
			int offset=0;
			String REGEX = "(?i)^=";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "equal", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^:=.*")){
			int offset=0;
			String REGEX = "(?i)^:=";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "assign", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^:.*")){
			int offset=0;
			String REGEX = "(?i)^:";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "colon", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^;.*")){
			int offset=0;
			String REGEX = "(?i)^;";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "semicolon", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^,.*")){
			int offset=0;
			String REGEX = "(?i)^,";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "comma", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\(\\..*")){
			int offset=0;
			String REGEX = "(?i)^\\(\\.";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "lbracket", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\.\\).*")){
			int offset=0;
			String REGEX = "(?i)^\\.\\)";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "rbracket", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\(.*")){
			int offset=0;
			String REGEX = "(?i)^\\(";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "lparen", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\).*")){
			int offset=0;
			String REGEX = "(?i)^\\)";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "rparen", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\..*")){
			int offset=0;
			String REGEX = "(?i)^\\.";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "period", chomp.substring(0,offset)); //print the token name then the part that matched
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\{.*")){
			int offset=0;
			String REGEX = "(?i)^\\{";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "langlebrack", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\}.*")){
			int offset=0;
			String REGEX = "(?i)^\\}";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "ranglebrack", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		//This is to handle the types of identifiers
		else if (input.matches("(?i)^[a-z]([a-z]|[0-9])*.*")){
			int offset=0;
			String REGEX = "(?i)^[a-z]([a-z]|[0-9])*";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "identifier", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^[0-9][0-9]*.*")){
			int offset=0;
			String REGEX = "(?i)^[0-9][0-9]*";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "number", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\'([a-z]|[0-9])\\'.*")){
			int offset=0;
			String REGEX = "(?i)^\\'([a-z]|[0-9])\\'";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "litchar", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		else if (input.matches("(?i)^\\'([a-z]|[0-9])*\\'.*")){
			int offset=0;
			String REGEX = "(?i)^\\'([a-z]|[0-9])*\\'";
			Pattern pattern = Pattern.compile(REGEX);
			Matcher matcher =   pattern.matcher(input);
			String chomp = input;
			while (matcher.find()){ //while the regex is true...
			offset = matcher.end(); // count how many characters the offset takes up
			}
			p.printf("%-15s %15s\n", "quotestring", chomp.substring(0,offset)); //print the token name then the part
			input = input.substring(offset); //remove the part that matches regex from the input
			getsym(input, p, lineCounter); //recursive call with the remaining string being the input (if there is any that is)
			return;
		}
		
		//This is to handle errors
		else{
			p.printf("%-15s %15s\n", "Error", input);
			System.out.println("There was an error. Please check LexicalOutput.txt to see where.");
		}
		
	}

	public static void main(String args[]) { 
		String inputFile= "LexicalInput.txt"; //input file to get tokenized. Change this to test different files.
		System.out.println("Looking for input file: " +inputFile);
		
		InputStream ins = null; // raw byte-stream
		Reader r = null; // cooked reader
		BufferedReader br = null; // buffered for readLine()
		try {
	    	String s;
			int counter = 0;
			PrintWriter writer = new PrintWriter("LexicalOutput.txt", "UTF-8");
	    	ins = new FileInputStream(inputFile);
	    	r = new InputStreamReader(ins, "UTF-8"); // leave charset out for default
	    	br = new BufferedReader(r);
			
			writer.printf("%-15s %15s\n", "LEXEME", "SPELLING"); //writes the headers to the text file
				
	    	while ((s = br.readLine()) != null) {
				counter = counter+1;
				getsym(s, writer, counter);
			}
			
			writer.printf("%-15s %15s\n", "eofsym", "eofsym"); //writes the end of symbol to signal the end
			
			writer.close(); //closes the writer
			ins.close(); //closes the input stream
			r.close();
			br.close();
		}
	
		catch (Exception e) {
	    	System.out.println("The input file was not found. This program will now stop"); // exception message
		}
		System.out.println("The program has finished running.");
		System.out.println("Output file: LexicalOutput.txt created.");s
	}	
}