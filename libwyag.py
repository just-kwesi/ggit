import argparse
import collections
import configparser
from datetime import datetime
import grp, pwd
from fnmatch import fnmatch
import hashlib
from math import ceil
import os
import re
import sys
import zlib

argparser = argparse.ArgumentParser(description="Unendlichs' content tracker")

argsubparsers = argparser.add_subparsers(title="Commands", dest="command")
argsubparsers.required  = True

def main(argv=sys.argv[1:]):
    args = argparser.parse_args(argv)

    match args.command:
        case "add"          : cmd_add(args)
        case "cat-file"     : cmd_cat_file(args)
        case "check-ignore" : cmd_check_ignore(args)
        case "checkout"     : cmd_checkout(args)
        case "commit"       : cmd_commit(args)
        case "hash-object"  : cmd_hash_object(args)
        case "init"         : cmd_init(args)
        case "log"          : cmd_log(args)
        case "ls-files"     : cmd_ls_files(args)
        case "ls-tree"      : cmd_ls_tree(args)
        case "rev-parse"    : cmd_rev_parse(args)
        case "rm"           : cmd_rm(args)
        case "show-ref"     : cmd_show_ref(args)
        case "status"       : cmd_status(args)
        case "tag"          : cmd_tag(args)
        case _              : print("Bad Command")


class GitRepository(object):
    """A git repository"""
    
    worktree = None
    gitdir = None
    conf = None
    
    def __init__(self, path, force=False) -> None:
        self.worktree = path
        self.gitdir = os.path.join(path, ".git")
        
        if not(force or os.path.isdir(self.gitdir)):
            raise Exception("Not a Git repository %s" % path)
        
        # Read configuration file in .git/config
        self.conf = configparser.ConfigParser()
        cf = repo_file(self,"config")
        
        if cf and os.path.exists(cf):
            self.conf.read([cf])
        elif not force:
            raise Exception("Configuration file is missing")
        
        if not force:
            vers = int(self.conf.get("core","repositoryformatversion"))
            if vers !=0:
                raise Exception('Unsupported repositoryformatversion %s' % vers)
            

def repo_path(repo, *path):
    """Compute path under repo's gitdir."""
    return os.path.join(repo.gitdir, *path)

def repo_file(repo, *path, mkdir=False):
    """Same as repo_path, but create dirname(*path) if absent.  For
example, repo_file(r, \"refs\", \"remotes\", \"origin\", \"HEAD\") will create
.git/refs/remotes/origin."""

    if repo_dir(repo, *path[:-1], mkdir=mkdir):
        return repo_path(repo, *path)

def repo_dir(repo, *path, mkdir=False):
    """Same as repo_path, but mkdir *path if absent if mkdir."""

    path = repo_path(repo, *path)

    if os.path.exists(path):
        if (os.path.isdir(path)):
            return path
        else:
            raise Exception("Not a directory %s" % path)

    if mkdir:
        os.makedirs(path)
        return path
    else:
        return None


def repo_create(path):
    """create a new repository at path"""
    
    repo = GitRepository(path,True)
    
    # first make sure path is empty or doesn't exist
    
    if os.path.exists(repo.worktree):
        if not os.path.isdir(repo.worktree):
            raise Exception ("%s is not a directory!" % path)
        if os.path.exists(repo.gitdir) and os.listdir(repo.gitdir):
            raise Exception("%s is not empty!" % path)
    else:
        os.makedirs(repo.worktree)
        
    
    assert repo_dir(repo, "branches", mkdir=True)
    assert repo_dir(repo, "objects", mkdir=True)
    assert repo_dir(repo, "refs", "tags", mkdir=True)
    assert repo_dir(repo, "refs", "heads", mkdir=True)
    
    # .git/description
    with open(repo_file(repo, "description"), "w") as f:
        f.write("Unnamed repository: edit this file 'description' to name this repository.\n")
    
    # .git/Head
    with open(repo_file(repo,"HEAD"),'w') as f:
        f.write('ref: refs/heads/master\n')
        
    with open(repo_file(repo,"config"), 'w') as f:
        config = repo_default_config()
        config.write(f)
    
    return repo

def repo_find(path=".", required=True):
    path = os.path.realpath(path)
    
    if os.path.isdir(os.path.join(path, ".git")):
        return GitRepository(path)

    # if we haven't returned, recurse in the parent if w
    parent = os.path.realpath(os.path.join(path,".."))
    
    if parent == path:
        # Bottom case
        # os.path.join("/", "..") == "/":
        # If parent==path, then path is root.
        if required:
            raise Exception("No git directory.")
        else:
            return None
    
    # recursive case
    return repo_find(parent,required)

def repo_default_config():
    ret = configparser.ConfigParser()
    
    ret.add_section("core")
    ret.set("core", "repositoryformatversion", "0")
    ret.set("core", "filemode", "false")
    ret.set("core", "bare", "false")

    return ret



class GitObject (object):
    def __init__(self,data=None):
        if data != None:
            self.deserialize(data)
        else:
            self.init()
            
    def init(self):
        pass
    
    def deserialize(self,data):
        raise NotImplementedError
    def serialize(self,repo):
        raise NotImplementedError
    
class GitBlob(GitObject):
    fmt=b'blob'
    
    def serialize(self):
        return self.blobData
    
    def deserialize(self,data):
        self.blobData = data

class GitCommit(GitObject):
    fmt=b'commit'
    
    def deserialize(self, data):
        self.kvlm = kvlm_parse(data)
    def serialize(self, repo):
        return kvlm_serialize(self.kvlm)
    def init(self):
        self.kvlm = dict()

class GitTreeLeaf(object):
    def __init__(self,mode,path,sha):
        self.mode = mode
        self.path = path
        self.sha = sha
        
class GitTree(GitObject):
    fmt=b'tree'
    
    def deserialize(self, data):
        self.items = tree_parse(data)
        
    def serialize(self):
        return tree_serialize(self)
    
    def init(self):
        self.items = list()

class GitTag(GitObject):
    fmt=b'tag'
    

class GitIndexEntry(object):
    def __init__(self, ctime=None, mtime=None, dev=None, ino=None, mode_type=None, mode_perms=None, uid=None, gid=None, fsize=None, sha=None, flag_assumee_valid=None, flag_stage=None, name=None):
        
        # The last time a file's metadata changed. This is a pair
        #  (timestamp in seconds, nanoseconds) in UTC.
        self.ctime = ctime
        # the last time a file's content changed. This is a pair
        #  (timestamp in seconds, nanoseconds) in UTC.
        self.mtime = mtime
        # the id of the device containing this file.
        self.dev = dev
        # the file;s inode number
        self.ino = ino
        # the object type, either b1000 (regular), b1010 (symlink),
        # b1110 (gitlink)
        self.mode_type = mode_type
        # the object permissions, as an integer
        self.mode_perms = mode_perms
        # user id of the owner
        self.uid = uid
        # groupd id of the owner
        self.gid = gid
        # size of the object, in bytes
        self.fsize= fsize
        # the object's Sha
        self.sha = sha
        self.flag_assume_valid = flag_assumee_valid
        self.flag_stage = flag_stage
        # Name of the object (full path this time!)
        self.name = name

class GitIndex (object):
    version = None
    entries = []
    # ext = None
    # sha = None
    
    def __init__(self, version=2, entries=None):
        if not entries:
            entries = list()
        self.version = version
        self.entries = entries

class GitIgnore(object):
    absolute = None
    scoped = None

    def __init__(self, absolute, scoped):
        self.absolute = absolute
        self.scoped = scoped
        
def gitignore_read(repo):
    ret = GitIgnore(absolute=list(), scoped=dict())

    # Read local configuration in .git/info/exclude
    repo_file = os.path.join(repo.gitdir, "info/exclude")
    if os.path.exists(repo_file):
        with open(repo_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    # Global configuration
    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")
    global_file = os.path.join(config_home, "git/ignore")

    if os.path.exists(global_file):
        with open(global_file, "r") as f:
            ret.absolute.append(gitignore_parse(f.readlines()))

    # .gitignore files in the index
    index = index_read(repo)

    for entry in index.entries:
        if entry.name == ".gitignore" or entry.name.endswith("/.gitignore"):
            dir_name = os.path.dirname(entry.name)
            contents = object_read(repo, entry.sha)
            lines = contents.blobdata.decode("utf8").splitlines()
            ret.scoped[dir_name] = gitignore_parse(lines)
    return ret

def check_ignore1(rules, path):
    result = None
    for (pattern, value) in rules:
        if fnmatch(path, pattern):
            result = value
    return result

def check_ignore_scoped(rules, path):
    parent = os.path.dirname(path)
    while True:
        if parent in rules:
            result = check_ignore1(rules[parent], path)
            if result != None:
                return result
        if parent == "":
            break
        parent = os.path.dirname(parent)
    return None

def check_ignore(rules, path):
    if os.path.isabs(path):
        raise Exception("This function requires path to be relative to the repository's root")

    result = check_ignore_scoped(rules.scoped, path)
    if result != None:
        return result

    return check_ignore_absolute(rules.absolute, path)

def check_ignore_absolute(rules, path):
    parent = os.path.dirname(path)
    for ruleset in rules:
        result = check_ignore1(ruleset, path)
        if result != None:
            return result
    return False # This is a reasonable default at this point.

def index_read(repo):
    index_file = repo_file(repo, "index")
    
    # New repositories have no index
    if not os.path.exists(index_file):
        return GitIndex()
    
    with open(index_file, 'rb') as f:
        raw = f.read()
    
    header = raw[:12]
    signature = header[:4]
    assert signature == b"DIRC" # Stands for "DirCache"
    version = int.from_bytes(header[4:8], byteorder='big')
    assert version == 2, "wyag only supports index file version 2"
    count = int.from_bytes(header[8:12],"big")
    
    entries = list()
    
    content = raw[12:]
    idx = 0 
    
    for i in range(0,count):
        #  Read creation time, as a unix timestamp (seconds since 
        # 1990-01-01 00:00:00, the epoch)
        ctime_s = int.from_bytes(content[idx: idx+4], "big")
        # Read creation time, as nanoseconds after the timestamps
        # for extra precision.
        ctime_ns = int.from_bytes(content[idx+4: idx+8], "big")
        # Same for modification time: first seconds from epoch.
        mtime_s = int.from_bytes(content[idx+8: idx+12], "big")
        # Then extra nanoseconds
        mtime_ns = int.from_bytes(content[idx+12: idx+16], "big")
        # Device ID
        dev = int.from_bytes(content[idx+16: idx+20], "big")
        # Inode
        ino = int.from_bytes(content[idx+20: idx+24], "big")
        # Ignored.
        unused = int.from_bytes(content[idx+24: idx+26], "big")
        assert 0 == unused
        mode = int.from_bytes(content[idx+26: idx+28], "big")
        mode_type = mode >> 12
        assert mode_type in [0b1000, 0b1010, 0b1110]
        mode_perms = mode & 0b0000000111111111
        # User ID
        uid = int.from_bytes(content[idx+28: idx+32], "big")
        # Group ID
        gid = int.from_bytes(content[idx+32: idx+36], "big")
        # Size
        fsize = int.from_bytes(content[idx+36: idx+40], "big")
        # SHA (object ID).  We'll store it as a lowercase hex string
        # for consistency.
        sha = format(int.from_bytes(content[idx+40: idx+60], "big"), "040x")
        # Flags we're going to ignore
        flags = int.from_bytes(content[idx+60: idx+62], "big")
        # Parse flags
        flag_assume_valid = (flags & 0b1000000000000000) != 0
        flag_extended = (flags & 0b0100000000000000) != 0
        assert not flag_extended
        flag_stage =  flags & 0b0011000000000000
        # Length of the name.  This is stored on 12 bits, some max
        # value is 0xFFF, 4095.  Since names can occasionally go
        # beyond that length, git treats 0xFFF as meaning at least
        # 0xFFF, and looks for the final 0x00 to find the end of the
        # name --- at a small, and probably very rare, performance
        # cost.
        name_length = flags & 0b0000111111111111

        # We've read 62 bytes so far.
        idx += 62
        
        if name_length < 0xFFF:
            assert content[idx + name_length] == 0x00
            raw_name = content[idx:idx+name_length]
            idx += name_length + 1
        else:
            print(f"Notice: name is 0x{name_length:X} bytes long.")
            # this probably wasn't tested enough. It works with a 
            # path of exactly 0xFFF bytes. Any extra bytes broke
            # something between git, my shell and my filesystem
            null_idx = content.find(b'\x00', idx + 0xFFF)
            raw_name = content[idx: null_idx]
            idx = null_idx + 1
        
        # just parse the name as utf8
        name = raw_name.decode('utf8')
        
        # and we add this entry to our list.
        entries.append(GitIndexEntry(ctime=(ctime_s,ctime_ns), mtime=(mtime_s,mtime_ns), dev=dev, ino=ino, mode_type=mode_type, mode_perms=mode_perms,uid=uid,gid=gid,fsize=fsize,sha=sha,flag_assumee_valid=flag_assume_valid,flag_stage=flag_stage,name=name))
    
    return GitIndex(version=version,entries=entries) 


def tree_parse_one(raw,start=0):
    # find the space terminator of the mode
    x = raw.find(b' ', start)
    assert x-start == 5 or x-start==6
    
    # read the mode
    mode = raw[start:x]
    if len(mode) == 5:
        # Normalize to six bytes
        mode = b"0" + mode
        
    # Find the NULL terminator of the path
    y = raw.find(b'\x00',x)
    # and read the path
    path = raw[x+1:y]
    
    # Read the SHA...
    raw_sha = int.from_bytes(raw[y+1:y+21], 'big')
    #  and convert it into an hex string, padded to 4o chars
    # with zeros if needed
    sha = format(raw_sha, "040x")
    return y+21, GitTreeLeaf(mode,path.decode('utf8'),sha)

def tree_parse(raw):
    pos = 0
    max = len(raw)
    ret = list()
    while pos < max:
        pos, data = tree_parse_one(raw,pos)
        ret.append(data)
    return ret


def tree_leaf_sort_key(leaf):
    if leaf.mode.startswith(b"10"):
        return leaf.path
    else:
        return leaf.path + "/"
    
def tree_serialize(obj):
    obj.items.sort(key=tree_leaf_sort_key)
    ret = b''
    
    for i in obj.items:
        ret+=i.mode
        ret+=b' '
        ret+=i.path.encode("utf8")
        ret+=b'\x00'
        sha=int(i.sha,16)
        ret+=sha.to_bytes(20,byteorder="big")
    return ret
    
        
def object_read(repo, sha):
    """Read object sha from Git repository repo.  Return a
    GitObject whose exact type depends on the object."""

    path = repo_file(repo, "objects", sha[0:2], sha[2:])

    if not os.path.isfile(path):
        return None

    with open (path, "rb") as f:
        raw = zlib.decompress(f.read())

        # Read object type
        x = raw.find(b' ')
        fmt = raw[0:x]

        # Read and validate object size
        y = raw.find(b'\x00', x)
        size = int(raw[x:y].decode("ascii"))
        if size != len(raw)-y-1:
            raise Exception(f"Malformed object {sha}: bad length")

        # Pick constructor
        match fmt:
            case b'commit' : c=GitCommit
            case b'tree'   : c=GitTree
            case b'tag'    : c=GitTag
            case b'blob'   : c=GitBlob
            case _:
                raise Exception(f"Unknown type {fmt.decode('ascii')} for object {sha}")

        # Call constructor and return object
        return c(raw[y+1:])

def object_write(obj,repo=None):
    data = obj.serialize()
    
    # add header
    result = obj.fmt + b' ' + str(len(data)).encode() + b'\x00' + data
    
    # compute hash
    sha = hashlib.sha1(result).hexdigest()
    
    if repo:
        # compute path
        path = repo_file(repo,'objects', sha[0:2], sha[2:], mkdir=True)
        
        if not os.path.exists(path):
            with open(path, 'wb') as f:
                # compress and write
                f.write(zlib.compress(result))
    return sha

def object_hash(fd, fmt, repo=None):
    """Hash object, writing it to the repo if provided"""
    data = fd.read()
    
    # choose constructor base on the fmt argument
    match fmt:
        case b'commit' : obj = GitCommit(data)
        case b'tag' : obj = GitTag(data)
        case b'tree' : obj = GitTree(data)
        case b'blob' : obj = GitBlob(data)
        case _: raise Exception(f"Unknown format: {fmt}!")
        
    return object_write(obj,repo)


def kvlm_parse(raw,start=0,dct = None):
    if not dct:
        dct = {}
        # you cannot declare the argument as dct = dict() or all call to 
        # the functions will endlessly grow the same dict
        
    # this function is recursive: it reads a key/value pair, then call 
    # itself again with the new position. so we first need to know,
    # where we are: at a keyword, or already in a messageQ
    
    # we search for the next space and the next newline.
    spc = raw.find(b' ', start)
    nl = raw.find(b'\n', start)
    
    # if the space appear before newline, we have a keyword. otherwise,
    # it's the final message, which we just read to the end of the file.
    
    # Base case
    # ===========================
    # if newline appears first (or there's no space at all, in which
    # case find returns -1), we assume a blank line. a blank line meands
    # means the remainder of the data is the message. we store it in the 
    # dictionary, None as the key, and return
    
    if (spc < 0) or (nl < spc):
        assert nl == start
        dct[None] = raw[start+1:]
        return dct
    
    # recursive case
    # =============
    # we read the key/value pair and recurse for the next
    key = raw[start:spc]
    
    
    # find the end of the value. Continuation lines begin with a space
    # so we loop until a '\n' not followed by a space
    end = start
    while True:
        end = raw.find(b'\n', end + 1)
        if raw[end+1] != ord(' '): break
        
    # grab the value
    # also, drop the leading space on continuation lines
    value = raw[spc+1:end].replace(b'\n ', b'\n')
    
    # don't overwrite the existing data contents
    if key in dct:
        if type(dct[key]) == list:
            dct[key].append(value)
        else:
            dct[key] = [dct[key], value]
    else:
        dct[key] = value
        
    return kvlm_parse(raw, start=end+1,dct=dct)

def kvlm_serialize(kvlm):
    ret = b''
    
    # output fields
    for k in kvlm.keys():
        # skip the message itself
        if k == None: continue
        val = kvlm[k]
        
        if type(val) != list:
            val = [val]
        for v in val:
            ret += k + b' ' + (v.replace(b'\n', b'\n ')) + b'\n'
    
    ret += b'\n' + kvlm[None]
    
    return ret
        

def ref_resolve(repo, ref):
    path = repo_file(repo, ref)
    
    # Sometimes, an indirect reference may be broken. This is normal
    # in one specific case: we're looking for HEAD on a new repository
    # with no commits. In that case, .git/HEAD points to 
    # "ref: refs/heads/main". but .git/refs/heads/main doesn't exist
    # yet (since there's no commit for it refer to).
    if not os.path.isfile(path):
        return None
    
    with open(path, 'r') as fp:
        data = fp.read()[:-1]
        # drop final \n ^^^^^
    if data.startswith("ref: "):
        return ref_resolve(repo, data[5:])
    else:
        return data

def ref_list(repo,path=None):
    if not path:
        path = repo_dir(repo, "refs")
    
    ret = dict()
    # Git show refs sorted. To do the same, we sort the output of listdir
    for f in sorted(os.listdir(path)):
        can = os.path.join(path, f)
        if os.path.isdir(can):
            ret[f] = ref_list(repo,can)
        else:
            ret[f] = ref_resolve(repo,can)
    return ret

def object_resolve(repo, name):
    """Resolve name to an object hash in repo
    This function is aware of:
    
    -the HEAD literal
    - short and long hashed
    - tags
    - branches
    - remote branches
    """
    
    candidates = list()
    hashRe = re.compile(r"^[0-9A-Fa-f]{4,40}$")
    
    # Empty string? Abort.
    if not name.strip():
        return None
    
    # HEAD is nonambiguos
    if name == "HEAD":
        return [ ref_resolve(repo, 'HEAD')]
    
    # if it's a hex string. try for a hash
    if hashRe.match(name):
        # this may be a hash, either small or full. 4 seems to be the 
        # minimal length for git to consider something a short hash.
        # This limit is documented in man git-rev-parse
        name = name.lower()
        prefix = name[0:2]
        path = repo_dir(repo, "objects", prefix, mkdir=False)
        if path:
            rem = name[2:]
            for f in os.listdir(path):
                if f.startswith(rem):
                    candidates.append(prefix+f)
        
    # Try for references.
    as_tag = ref_resolve(repo, "refs/tags/" + name)
    if as_tag: #did we find a tag?
        candidates.append(as_tag)
        
    as_branch = ref_resolve(repo, "refs/heads/" + name)
    if as_branch: #did we find a branch?
        candidates.append(as_branch)
        
    return candidates

def object_find(repo, name, fmt=None, follow=True):
    sha = object_resolve(repo, name)
    
    if not sha:
        raise Exception(f"No such reference {name}.")
    
    if len(sha) > 1:
        raise Exception("Ambiguous reference {name}: Candidates are:\n - {'\n - '.join(sha)}.")
    
    sha = sha[0]
    
    if not fmt:
        return sha
    
    while True:
        obj = object_read(repo, sha)
        
        if obj.fmt == fmt:
            return sha
        
        if not follow:
            return None
        
        # follo tags
        if obj.fmt == b'tag':
            sha = obj.kvlm[b'object'].decode("ascii")
        elif obj.fmt == b'commit' and fmt == b'tree':
            sha = obj.kvlm[b'tree'].decode("ascii")
        else:
            return None


def gitignore_parse1(raw):
    raw = raw.strip() # Remove leading/trailing spaces

    if not raw or raw[0] == "#":
        return None
    elif raw[0] == "!":
        return (raw[1:], False)
    elif raw[0] == "\\":
        return (raw[1:], True)
    else:
        return (raw, True)
    
    
def gitignore_parse(lines):
    ret = list()

    for line in lines:
        parsed = gitignore_parse1(line)
        if parsed:
            ret.append(parsed)

    return ret

def branch_get_active(repo):
    with open(repo_file(repo, "HEAD"), "r") as f:
        head = f.read()

    if head.startswith("ref: refs/heads/"):
        return(head[16:-1])
    else:
        return False

def cmd_status_branch(repo):
    branch = branch_get_active(repo)
    if branch:
        print(f"On branch {branch}.")
    else:
        print(f"HEAD detached at {object_find(repo, 'HEAD')}")

def tree_to_dict(repo, ref, prefix=""):
    ret = dict()
    tree_sha = object_find(repo, ref, fmt=b"tree")
    tree = object_read(repo, tree_sha)

    for leaf in tree.items:
        full_path = os.path.join(prefix, leaf.path)

        # We read the object to extract its type (this is uselessly
        # expensive: we could just open it as a file and read the
        # first few bytes)
        is_subtree = leaf.mode.startswith(b'04')

        # Depending on the type, we either store the path (if it's a
        # blob, so a regular file), or recurse (if it's another tree,
        # so a subdir)
        if is_subtree:
            ret.update(tree_to_dict(repo, leaf.sha, full_path))
        else:
            ret[full_path] = leaf.sha
    return ret


def index_write(repo, index):
    with open(repo_file(repo, "index"), "wb") as f:

        # HEADER

        # Write the magic bytes.
        f.write(b"DIRC")
        # Write version number.
        f.write(index.version.to_bytes(4, "big"))
        # Write the number of entries.
        f.write(len(index.entries).to_bytes(4, "big"))

        # ENTRIES

        idx = 0
        for e in index.entries:
            f.write(e.ctime[0].to_bytes(4, "big"))
            f.write(e.ctime[1].to_bytes(4, "big"))
            f.write(e.mtime[0].to_bytes(4, "big"))
            f.write(e.mtime[1].to_bytes(4, "big"))
            f.write(e.dev.to_bytes(4, "big"))
            f.write(e.ino.to_bytes(4, "big"))

            # Mode
            mode = (e.mode_type << 12) | e.mode_perms
            f.write(mode.to_bytes(4, "big"))

            f.write(e.uid.to_bytes(4, "big"))
            f.write(e.gid.to_bytes(4, "big"))

            f.write(e.fsize.to_bytes(4, "big"))
            # @FIXME Convert back to int.
            f.write(int(e.sha, 16).to_bytes(20, "big"))

            flag_assume_valid = 0x1 << 15 if e.flag_assume_valid else 0

            name_bytes = e.name.encode("utf8")
            bytes_len = len(name_bytes)
            if bytes_len >= 0xFFF:
                name_length = 0xFFF
            else:
                name_length = bytes_len

            # We merge back three pieces of data (two flags and the
            # length of the name) on the same two bytes.
            f.write((flag_assume_valid | e.flag_stage | name_length).to_bytes(2, "big"))

            # Write back the name, and a final 0x00.
            f.write(name_bytes)
            f.write((0).to_bytes(1, "big"))

            idx += 62 + len(name_bytes) + 1

            # Add padding if necessary.
            if idx % 8 != 0:
                pad = 8 - (idx % 8)
                f.write((0).to_bytes(pad, "big"))
                idx += pad

def rm(repo, paths, delete=True, skip_missing=False):
    # Find and read the index
    index = index_read(repo)

    worktree = repo.worktree + os.sep

    # Make paths absolute
    abspaths = set()
    for path in paths:
        abspath = os.path.abspath(path)
        if abspath.startswith(worktree):
            abspaths.add(abspath)
        else:
            raise Exception(f"Cannot remove paths outside of worktree: {paths}")

    # The list of entries to *keep*, which we will write back to the
    # index.
    kept_entries = list()
    # The list of removed paths, which we'll use after index update
    # to physically remove the actual paths from the filesystem.
    remove = list()

    # Now iterate over the list of entries, and remove those whose
    # paths we find in abspaths.  Preserve the others in kept_entries.
    for e in index.entries:
        full_path = os.path.join(repo.worktree, e.name)

        if full_path in abspaths:
            remove.append(full_path)
            abspaths.remove(full_path)
        else:
            kept_entries.append(e) # Preserve entry

    # If abspaths is empty, it means some paths weren't in the index.
    if len(abspaths) > 0 and not skip_missing:
        raise Exception(f"Cannot remove paths not in the index: {abspaths}")

    # Physically delete paths from filesystem.
    if delete:
        for path in remove:
            os.unlink(path)

    # Update the list of entries in the index, and write it back.
    index.entries = kept_entries
    index_write(repo, index)

def add(repo, paths, delete=True, skip_missing=False):

    # First remove all paths from the index, if they exist.
    rm (repo, paths, delete=False, skip_missing=True)

    worktree = repo.worktree + os.sep

    # Convert the paths to pairs: (absolute, relative_to_worktree).
    # Also delete them from the index if they're present.
    clean_paths = set()
    for path in paths:
        abspath = os.path.abspath(path)
        if not (abspath.startswith(worktree) and os.path.isfile(abspath)):
            raise Exception(f"Not a file, or outside the worktree: {paths}")
        relpath = os.path.relpath(abspath, repo.worktree)
        clean_paths.add((abspath,  relpath))

    # Find and read the index.  It was modified by rm.  (This isn't
    # optimal, good enough for wyag!)
    #
    # @FIXME, though: we could just move the index through
    # commands instead of reading and writing it over again.
    index = index_read(repo)

    for (abspath, relpath) in clean_paths:
        with open(abspath, "rb") as fd:
            sha = object_hash(fd, b"blob", repo)

            stat = os.stat(abspath)

            ctime_s = int(stat.st_ctime)
            ctime_ns = stat.st_ctime_ns % 10**9
            mtime_s = int(stat.st_mtime)
            mtime_ns = stat.st_mtime_ns % 10**9

            entry = GitIndexEntry(ctime=(ctime_s, ctime_ns), mtime=(mtime_s, mtime_ns), dev=stat.st_dev, ino=stat.st_ino,
                                  mode_type=0b1000, mode_perms=0o644, uid=stat.st_uid, gid=stat.st_gid,
                                  fsize=stat.st_size, sha=sha, flag_assume_valid=False,
                                  flag_stage=False, name=relpath)
            index.entries.append(entry)

    # Write the index back
    index_write(repo, index)
    

def gitconfig_read():
    xdg_config_home = os.environ["XDG_CONFIG_HOME"] if "XDG_CONFIG_HOME" in os.environ else "~/.config"
    configfiles = [
        os.path.expanduser(os.path.join(xdg_config_home, "git/config")),
        os.path.expanduser("~/.gitconfig")
    ]

    config = configparser.ConfigParser()
    config.read(configfiles)
    return config

def gitconfig_user_get(config):
    if "user" in config:
        if "name" in config["user"] and "email" in config["user"]:
            return f"{config['user']['name']} <{config['user']['email']}>"
    return None

def tree_from_index(repo, index):
    contents = dict()
    contents[""] = list()

    # Enumerate entries, and turn them into a dictionary where keys
    # are directories, and values are lists of directory contents.
    for entry in index.entries:
        dirname = os.path.dirname(entry.name)

        # We create all dictonary entries up to root ("").  We need
        # them *all*, because even if a directory holds no files it
        # will contain at least a tree.
        key = dirname
        while key != "":
            if not key in contents:
                contents[key] = list()
            key = os.path.dirname(key)

        # For now, simply store the entry in the list.
        contents[dirname].append(entry)

    # Get keys (= directories) and sort them by length, descending.
    # This means that we'll always encounter a given path before its
    # parent, which is all we need, since for each directory D we'll
    # need to modify its parent P to add D's tree.
    sorted_paths = sorted(contents.keys(), key=len, reverse=True)

    # This variable will store the current tree's SHA-1.  After we're
    # done iterating over our dict, it will contain the hash for the
    # root tree.
    sha = None

    # We ge through the sorted list of paths (dict keys)
    for path in sorted_paths:
        # Prepare a new, empty tree object
        tree = GitTree()

        # Add each entry to our new tree, in turn
        for entry in contents[path]:
            # An entry can be a normal GitIndexEntry read from the
            # index, or a tree we've created.
            if isinstance(entry, GitIndexEntry): # Regular entry (a file)

                # We transcode the mode: the entry stores it as integers,
                # we need an octal ASCII representation for the tree.
                leaf_mode = f"{entry.mode_type:02o}{entry.mode_perms:04o}".encode("ascii")
                leaf = GitTreeLeaf(mode = leaf_mode, path=os.path.basename(entry.name), sha=entry.sha)
            else: # Tree.  We've stored it as a pair: (basename, SHA)
                leaf = GitTreeLeaf(mode = b"040000", path=entry[0], sha=entry[1])

            tree.items.append(leaf)

        # Write the new tree object to the store.
        sha = object_write(tree, repo)

        # Add the new tree hash to the current dictionary's parent, as
        # a pair (basename, SHA)
        parent = os.path.dirname(path)
        base = os.path.basename(path) # The name without the path, eg main.go for src/main.go
        contents[parent].append((base, sha))

    return sha

def commit_create(repo, tree, parent, author, timestamp, message):
    commit = GitCommit() # Create the new commit object.
    commit.kvlm[b"tree"] = tree.encode("ascii")
    if parent:
        commit.kvlm[b"parent"] = parent.encode("ascii")

    # Trim message and add a trailing \n
    message = message.strip() + "\n"
    # Format timezone
    offset = int(timestamp.astimezone().utcoffset().total_seconds())
    hours = offset // 3600
    minutes = (offset % 3600) // 60
    tz = "{}{:02}{:02}".format("+" if offset > 0 else "-", hours, minutes)

    author = author + timestamp.strftime(" %s ") + tz

    commit.kvlm[b"author"] = author.encode("utf8")
    commit.kvlm[b"committer"] = author.encode("utf8")
    commit.kvlm[None] = message.encode("utf8")

    return object_write(commit, repo)

# init repo
argsp = argsubparsers.add_parser('init', help="Initiate a new, empty repository")
argsp.add_argument("path", metavar='directory',nargs='?',default=".",help="Where to create the repository")

# add cat-file command
argsp = argsubparsers.add_parser('cat-file', help="Provide content of objects in a repository")
argsp.add_argument("type", metavar='type', choices=['blob','commit','tag','tree'] ,help="Speccify Type of object to retrieve")
argsp.add_argument('object', metavar='object', help="Object to display")


# hash object arg added 
argsp = argsubparsers.add_parser('hash-object', help='Compute object ID and optionally creates a blob from a file')

argsp.add_argument("-t", metavar='type', choices=['blob','commit','tag','tree'] ,help="Speccify the type")

argsp.add_argument('-w',dest='write',action="store_true", help="Actually write the object into the database")

argsp.add_argument('path', help='Read object from <file>')

# log
argsp = argsubparsers.add_parser('log',help="Display the history of a given commit.")
argsp.add_argument("commit", default="Head", nargs='?', help="Commit to start at.")

# ls-tree
argsp = argsubparsers.add_parser("ls-tree", help="Pretty-print a tree object.")
argsp.add_argument("-r", dest="recursive", action="store_true", help="Recurse into sub-trees")

argsp.add_argument("tree",help="A tree-ish object.")

# checkout
argsp = argsubparsers.add_parser("checkout", help="Checkout a commit inside of a directory.")
argsp.add_argument("commit", help="The commit or tree to checkout.")
argsp.add_argument("path", help="The Empty directory to checkout on.")

# show-ref
argsp = argsubparsers.add_parser("show-ref", help="List references.")

# tag
argsp = argsubparsers.add_parser("tag", help="List and create tags")
argsp.add_argument("-a", action="store_true", dest="create_tag_object", help="Whether to create a tag object")
argsp.add_argument("name", nargs="?", help="The new tag's name")
argsp.add_argument("object", default="HEAD", nargs="?", help="The object the new tag will point to")

# rev-parse
argsp = argsubparsers.add_parser('rev-parse', help="Parse revision (or other objects) identifiers")
argsp.add_argument("--wyag-type", metavar='type', dest="type", choices=["blob", "commit", "tag", "tree"], default=None, help="Specify the expected type")
argsp.add_argument("name", help='The name to parse')

# ls-files
argsp = argsubparsers.add_parser('ls-files', help = "List all the stage files")
argsp.add_argument("--verbose", action="store_true", help="Show everything")


# check igonre
argsp = argsubparsers.add_parser("check-ignore", help = "Check path(s) against ignore rules.")
argsp.add_argument("path", nargs="+", help="Paths to check")

# status
argsp = argsubparsers.add_parser("status", help = "Show the working tree status.")

# rm 
argsp = argsubparsers.add_parser("rm", help="Remove files from the working tree and the index.")
argsp.add_argument("path", nargs="+", help="Files to remove")

# add
argsp = argsubparsers.add_parser("add", help = "Add files contents to the index.")
argsp.add_argument("path", nargs="+", help="Files to add")

# commit
argsp = argsubparsers.add_parser("commit", help="Record changes to the repository.")
argsp.add_argument("-m", metavar="message", dest="message", help="Message to associate with this commit.")

def cmd_init(args):
    repo_create(args.path)

def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())

def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, object_find(repo,obj,fmt=fmt))

def cmd_hash_object(args):
    if args.write:
        repo = repo_find()
    else:
        repo = None
    
    with open(args.path, "rb") as fd:
        sha = object_hash(fd,args.type.encode(), repo)
        print(sha)

        
def cmd_log(args):
    repo = repo_find()
    
    print("digraph wyaglog{")
    print(" Node[shape=rect]")
    log_graphviz(repo,object_find(repo,args.commit), set())
    print("}")
    
def log_graphviz(repo,sha,seen):
    if sha in seen:
        return 
    seen.add(sha)
    
    commit = object_read(repo,sha)
    message = commit.kvlm[None].decode('utf8').strip()
    message = message.replace("\\","\\\\")
    message = message.replace("\"","\\\"")
    
    
    if "\n" in message:
        message = message[:message.index("\n")]
    
    print(f" c_{sha} [label=\"{sha[0:7]}: {message}\"]")
    assert commit.fmt ==b'commit'
    
    if not b'parent' in commit.kvlm.keys():
        # base case: the inital commit
        return
    
    parents = commit.kvlm[b'parent']
    if type(parents) != list:
        parents = [parents]
    for p in parents:
        p = p.decode('ascii')
        print(f" c_{sha} -> c_{p};")
        log_graphviz(repo,p,seen)

def cmd_ls_tree(args):
    repo = repo_find()
    ls_tree(repo, args.tree, args.recursive)

def ls_tree(repo, ref, recursive=None, prefix=""):
    sha = object_find(repo, ref, fmt=b"tree")
    obj = object_read(repo,sha)
    
    for item in obj.items:
        if len(item.mode) == 5:
            type = item.mode[0:1]
        else:
            type = item.mode[0:2]
        
        match type: # Determine the type.
            case b'04' : type = "tree"
            case b'10' : type = "blob" # a regular file.
            case b"12" : type = "blob" # A symlink. Blob contents is link target.
            case b"16" : type = "commit" # A submodule
            case _: raise Exception(f"Weird tree leaf mode {item.mode}")
            
        if not (recursive and type=='tree'): # This is a leaf
            print(f"{'0' * (6 - len(item.mode)) + item.mode.decode('ascii')} {type} {item.sha}\t{os.path.join(prefix, item.path)}")
        else: # this is a branch, recurse
            ls_tree(repo, item.sha, recursive, os.path.join(prefix, item.path))
    

def cmd_checkout(args):
    repo = repo_find()
    
    obj = object_read(repo,object_find(repo,args.commit))
    
    # if the object is a commit, we grab the tree
    if obj.fmt == b'commit':
        obj = object_read(repo, obj.kvlm[b'tree'].decode("ascii"))
        
    # Verify that path is an empty directory
    if os.path.exists(args.path):
        if not os.path.isdir(args.path):
            raise Exception(f"Not a directory {args.path}!")
        if os.listdir(args.path):
            raise Exception(f"Not empty {args.path}!")
    else:
        os.makedirs(args.path)
        
    tree_checkout(repo, obj, os.path.realpath(args.path))
    
def tree_checkout(repo, tree,path):
    for item in tree.items:
        obj = object_read(repo, item.sha)
        dest = os.path.join(path,item.path)
        
        if obj.fmt == b'tree':
            os.mkdir(dest)
            tree_checkout(repo, obj, dest)
        elif obj.fmt == b'blob':
            # @TODO Support symlinks (identified by mode 12****)
            with open(dest, 'wb') as f:
                f.write(obj.blobData)


def cmd_show_ref(args):
    repo = repo_find()
    refs = ref_list(repo)
    
    show_ref(repo, refs, prefix="refs")

def show_ref(repo, refs, with_hash=True, prefix=""):
    if prefix:
        prefix = prefix + "/"
    for k, v in refs.items():
        if type(v) == str and with_hash:
            print(f"{v} {prefix}{k}")
        elif type(v) == str:
            print(f"{prefix}{k}")
        else:
            show_ref(repo, v, with_hash=with_hash, prefix=f"{prefix}{k}")
            
            
def cmd_tag(args):
    repo = repo_find()
    
    if args.name:
        tag_create(repo, args.name, args.object, create_tag_object = args.create_tag_object)
    else:
        refs = ref_list(repo)
        show_ref(repo, refs["tags"], with_hash=False)

def tag_create(repo, name, ref, create_tag_object=False):
    # get the GitObject from the object reference
    sha = object_find(repo, ref)
    
    if create_tag_object:
        #  create tag object (commit)
        tag = GitTag()
        tag.kvlm = dict()
        tag.kvlm[b'object'] = sha.encode()
        tag.kvlm[b'type'] = b'commit'
        tag.kvlm[b"tag"] = name.encode()
        # Feel free to let the user give their name!
        # Notice you can fix this after commit, read on!
        tag.kvlm[b'tagger'] = b'Ggit <ggit@example.com>'
        # ...and a tag message!
        tag.kvlm[None] = b"A tag generated by ggit, which won't let you customize the message!\n"
        tag_sha = object_write(tag, repo)
        # create reference
        ref_create(repo, "tags/" + name, tag_sha)
    else:
        # create lightweight tag (ref)
        ref_create(repo, "tags/" + name, sha)
        
def ref_create(repo, ref_name,sha):
    with open(repo_file(repo, "refs/" + ref_name), 'w') as fp:
        fp.write(sha + "\n")

def cmd_rev_parse(args):
    if args.type:
        fmt = args.type.encode()
    else:
        fmt = None
    
    repo = repo_find()
    print(object_find(repo,args.name,fmt,follow=True))
    
    
def cmd_ls_files(args):
    repo = repo_find()
    index = index_read(repo)
    if args.verbose:
        print(f"Index file format v{index.version}, containing {len(index.entries)} entries.")

    for e in index.entries:
        print(e.name)
        if args.verbose:
            entry_type = { 0b1000: "regular file",
                           0b1010: "symlink",
                           0b1110: "git link" }[e.mode_type]
            print(f"  {entry_type} with perms: {e.mode_perms:o}")
            print(f"  on blob: {e.sha}")
            print(f"  created: {datetime.fromtimestamp(e.ctime[0])}.{e.ctime[1]}, modified: {datetime.fromtimestamp(e.mtime[0])}.{e.mtime[1]}")
            print(f"  device: {e.dev}, inode: {e.ino}")
            print(f"  user: {pwd.getpwuid(e.uid).pw_name} ({e.uid})  group: {grp.getgrgid(e.gid).gr_name} ({e.gid})")
            print(f"  flags: stage={e.flag_stage} assume_valid={e.flag_assume_valid}")
            print(f"  mode: {e.mode:o}")

def cmd_check_ignore(args):
    repo = repo_find()
    rules = gitignore_read(repo)
    for path in args.path:
        if check_ignore(rules, path):
            print(path)

def cmd_status(_):
    repo = repo_find()
    index = index_read(repo)

    cmd_status_branch(repo)
    cmd_status_head_index(repo, index)
    print()
    cmd_status_index_worktree(repo, index)
    
def cmd_status_head_index(repo, index):
    print("Changes to be committed:")

    head = tree_to_dict(repo, "HEAD")
    for entry in index.entries:
        if entry.name in head:
            if head[entry.name] != entry.sha:
                print("  modified:", entry.name)
            del head[entry.name] # Delete the key
        else:
            print("  added:   ", entry.name)

    # Keys still in HEAD are files that we haven't met in the index,
    # and thus have been deleted.
    for entry in head.keys():
        print("  deleted: ", entry)
        
def cmd_status_index_worktree(repo, index):
    print("Changes not staged for commit:")

    ignore = gitignore_read(repo)

    gitdir_prefix = repo.gitdir + os.path.sep

    all_files = list()

    # We begin by walking the filesystem
    for (root, _, files) in os.walk(repo.worktree, True):
        if root==repo.gitdir or root.startswith(gitdir_prefix):
            continue
        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, repo.worktree)
            all_files.append(rel_path)

    # We now traverse the index, and compare real files with the cached
    # versions.

    for entry in index.entries:
        full_path = os.path.join(repo.worktree, entry.name)

        # That file *name* is in the index

        if not os.path.exists(full_path):
            print("  deleted: ", entry.name)
        else:
            stat = os.stat(full_path)

            # Compare metadata
            ctime_ns = entry.ctime[0] * 10**9 + entry.ctime[1]
            mtime_ns = entry.mtime[0] * 10**9 + entry.mtime[1]
            if (stat.st_ctime_ns != ctime_ns) or (stat.st_mtime_ns != mtime_ns):
                # If different, deep compare.
                # @FIXME This *will* crash on symlinks to dir.
                with open(full_path, "rb") as fd:
                    new_sha = object_hash(fd, b"blob", None)
                    # If the hashes are the same, the files are actually the same.
                    same = entry.sha == new_sha

                    if not same:
                        print("  modified:", entry.name)

        if entry.name in all_files:
            all_files.remove(entry.name)

    print()
    print("Untracked files:")

    for f in all_files:
        # @TODO If a full directory is untracked, we should display
        # its name without its contents.
        if not check_ignore(ignore, f):
            print(" ", f)

def cmd_rm(args):
    repo = repo_find()
    rm(repo, args.path)

def cmd_add(args):
    repo = repo_find()
    add(repo, args.path)
    
def cmd_commit(args):
    repo = repo_find()
    index = index_read(repo)
    # Create trees, grab back SHA for the root tree.
    tree = tree_from_index(repo, index)

    # Create the commit object itself
    commit = commit_create(repo,
                           tree,
                           object_find(repo, "HEAD"),
                           gitconfig_user_get(gitconfig_read()),
                           datetime.now(),
                           args.message)

    # Update HEAD so our commit is now the tip of the active branch.
    active_branch = branch_get_active(repo)
    if active_branch: # If we're on a branch, we update refs/heads/BRANCH
        with open(repo_file(repo, os.path.join("refs/heads", active_branch)), "w") as fd:
            fd.write(commit + "\n")
    else: # Otherwise, we update HEAD itself.
        with open(repo_file(repo, "HEAD"), "w") as fd:
            fd.write("\n")