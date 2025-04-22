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
    
        
def object_read(repo,sha):
    """Read object sha from Git repository repo.  Return a
    GitObject whose exact type depends on the object."""
    
    path = repo_file(repo, 'objects', sha[0:2],sha[2:])
    
    if not os.path.isfile(path):
        return None
    
    with open(path,'rb') as f:
        raw = zlib.decompress(f.read())
        
        # read object type
        x = raw.find(b' ')
        fmt = raw[0:x]
        
        # read and validate object size
        y = raw.find(b'\x00', x)
        size = int(raw[x:y].decode('ascii'))
        if size != len(raw) - y - 1 :
            raise Exception(f"Malformed object {sha}: bad length")
        
        match fmt:
            case b'commit' : c=GitCommit
            case b'tree'   : c=GitTree
            case b'tag'    : c=GitTag
            case b'blob'   : c=GitBlob
            case _:
                raise Exception(f"Unknown type {fmt.decode("ascii")} for object {sha}")
            
            # call constructor and return object
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

def cmd_init(args):
    repo_create(args.path)

def cmd_cat_file(args):
    repo = repo_find()
    cat_file(repo, args.object, fmt=args.type.encode())

def cat_file(repo, obj, fmt=None):
    obj = object_read(repo, object_find(repo,obj,fmt=fmt))
    
def object_find(repo,name,fmt=None,follow=True):
    return None

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

